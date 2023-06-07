// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::Outcome;
use crate::{
    data_types::{
        Block, BlockAndRound, BlockProposal, Certificate, CertificateValue, ExecutedBlock,
        HashedValue, LiteVote, OutgoingMessage, Vote,
    },
    ChainError,
};
use linera_base::{
    crypto::{CryptoHash, KeyPair, PublicKey},
    data_types::{BlockHeight, RoundNumber, Timestamp},
    ensure,
    identifiers::{ChainId, Owner},
};
use linera_execution::committee::Epoch;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use rand_distr::{Distribution, WeightedAliasIndex};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};
use tracing::error;

const TIMEOUT: Duration = Duration::from_secs(10);

/// The specific state of a chain with multiple owners some of which are potentially faulty.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiOwnerFtManager {
    /// The co-owners of the chain, with their weights.
    pub owners: BTreeMap<Owner, (PublicKey, u128)>,
    /// The probability distribution for choosing a round leader.
    pub distribution: WeightedAliasIndex<u128>,
    /// Latest authenticated block that we have received.
    pub proposed: Option<BlockProposal>,
    /// Latest validated proposal that we have voted to confirm (or would have, if we are not a
    /// validator).
    pub locked: Option<Certificate>,
    /// Latest leader timeout certificate we have received.
    pub leader_timeout: Option<Certificate>,
    /// Latest vote we have cast, to validate or confirm.
    pub pending: Option<Vote>,
    /// Latest timeout vote we cast.
    pub timeout_vote: Option<Vote>,
    /// The validated blocks from rounds higher than `locked`.
    pub validated: BTreeMap<RoundNumber, Certificate>,
    /// The time after which we are ready to sign a timeout certificate for the current round.
    pub round_timeout: Timestamp,
}

impl MultiOwnerFtManager {
    pub fn new(
        owners: impl IntoIterator<Item = (Owner, (PublicKey, u128))>,
    ) -> Result<Self, ChainError> {
        let owners: BTreeMap<Owner, (PublicKey, u128)> = owners.into_iter().collect();
        let weights = owners.values().map(|(_, weight)| *weight).collect();
        let distribution = WeightedAliasIndex::new(weights)?;
        let round_timeout = Timestamp::now().saturating_add(TIMEOUT);

        Ok(MultiOwnerFtManager {
            owners,
            distribution,
            proposed: None,
            locked: None,
            leader_timeout: None,
            pending: None,
            timeout_vote: None,
            validated: Default::default(),
            round_timeout,
        })
    }

    /// Returns the round after the highest known leader timeout or validated block certificate.
    pub fn next_round(&self) -> RoundNumber {
        let validated = self.validated.keys().last().copied();
        let leader_timeout = self.leader_timeout.as_ref();
        leader_timeout
            .map(|certificate| certificate.round)
            .into_iter()
            .chain(validated)
            .max()
            .map_or(RoundNumber(0), |previous_round| {
                previous_round.try_add_one().unwrap_or(previous_round)
            })
    }

    /// Returns the most recent vote we cast.
    pub fn pending(&self) -> Option<&Vote> {
        self.pending.as_ref()
    }

    /// Verifies the safety of the block with respect to voting rules.
    ///
    /// We are allowed to vote for only one proposal in each round, but only if `locked.is_none()`
    /// or if one of `validated` contains the proposed block.
    pub fn check_proposed_block(
        &self,
        new_block: &Block,
        new_round: RoundNumber,
    ) -> Result<Outcome, ChainError> {
        let next_round = self.next_round();
        ensure!(next_round == new_round, ChainError::WrongRound(next_round));
        // Vote for at most one proposal per round.
        if let Some(pending) = &self.pending {
            if pending.value().block() == Some(new_block) && pending.round == new_round {
                return Ok(Outcome::Skip); // Same proposal we already voted for.
            }
            ensure!(
                new_round > pending.round,
                ChainError::MultipleBlockProposals
            );
        }
        if let Some((locked_block, locked_round)) = self.locked_block() {
            let is_new_block =
                |certificate: &Certificate| certificate.value().block() == Some(new_block);
            ensure!(
                *new_block == *locked_block || self.validated.values().any(is_new_block),
                ChainError::HasLockedBlock(new_block.height, locked_round)
            );
        }
        Ok(Outcome::Accept)
    }

    /// Checks if the next round has timed out, and signs a `LeaderTimeout`
    pub fn vote_leader_timeout(
        &mut self,
        chain_id: ChainId,
        height: BlockHeight,
        epoch: Epoch,
        key_pair: Option<&KeyPair>,
    ) -> bool {
        if Timestamp::now() < self.round_timeout {
            return false; // Round has not timed out yet.
        }
        let Some(key_pair) = key_pair else {
            return false; // We are not a chain owner.
        };
        let next_round = self.next_round();
        if let Some(leader_timeout) = &self.leader_timeout {
            if leader_timeout.round >= next_round {
                return false; // We already signed this timeout.
            }
        }
        let value = CertificateValue::LeaderTimeout {
            chain_id,
            height,
            epoch,
        };
        let vote = Vote::new(HashedValue::from(value), next_round, key_pair);
        self.timeout_vote = Some(vote);
        true
    }

    pub fn check_validated_block(
        &mut self,
        certificate: &Certificate,
    ) -> Result<Outcome, ChainError> {
        let next_round = self.next_round();
        let new_round = certificate.round;
        if let Some(Vote { value, round, .. }) = &self.pending {
            match value.inner() {
                CertificateValue::ConfirmedBlock { executed_block } => {
                    if Some(&executed_block.block) == certificate.value().block() {
                        return Ok(Outcome::Skip);
                    }
                }
                CertificateValue::ValidatedBlock { .. } => ensure!(
                    new_round >= *round,
                    ChainError::InsufficientRound(round.try_sub_one().unwrap())
                ),
                CertificateValue::LeaderTimeout { .. } => unreachable!(),
            }
        }
        if let Some((_, locked_round)) = self.locked_block() {
            ensure!(
                new_round >= locked_round,
                ChainError::InsufficientRound(locked_round)
            );
        }
        self.update_timeout(new_round);
        self.validated.insert(new_round, certificate.clone());
        ensure!(
            new_round == next_round,
            ChainError::InsufficientRound(next_round)
        );
        Ok(Outcome::Accept)
    }

    pub fn create_vote(
        &mut self,
        proposal: BlockProposal,
        messages: Vec<OutgoingMessage>,
        state_hash: CryptoHash,
        key_pair: Option<&KeyPair>,
    ) {
        // Record the proposed block, so it can be supplied to clients that request it.
        self.proposed = Some(proposal.clone());
        if let Some(key_pair) = key_pair {
            // Vote to validate.
            let BlockAndRound { block, round } = proposal.content;
            let executed_block = ExecutedBlock {
                block,
                messages,
                state_hash,
            };
            let vote = Vote::new(HashedValue::new_validated(executed_block), round, key_pair);
            self.pending = Some(vote);
        }
    }

    pub fn create_final_vote(&mut self, certificate: Certificate, key_pair: Option<&KeyPair>) {
        let Some(value) = certificate.value.clone().into_confirmed() else {
            error!("Unexpected value for final vote: {:?}", certificate.value());
            return;
        };
        let round = certificate.round;
        self.validated = round
            .try_add_one()
            .map(|round| self.validated.split_off(&round))
            .unwrap_or_default();
        self.locked = Some(certificate);
        if let Some(key_pair) = key_pair {
            // Vote to confirm. This is in the current round, so we can overwrite `pending`.
            self.pending = Some(Vote::new(value, round, key_pair));
        }
    }

    /// Resets the timer if `round` has just ended.
    fn update_timeout(&mut self, round: RoundNumber) {
        if self.next_round() <= round {
            let factor = round.0.saturating_add(2);
            let timeout = TIMEOUT.saturating_mul(u32::try_from(factor).unwrap_or(u32::MAX));
            self.round_timeout = Timestamp::now().saturating_add(timeout);
        }
    }

    /// Updates the round number and timer if the timeout certificate is from a higher round than
    /// any known certificate.
    pub fn handle_timeout_certificate(&mut self, certificate: Certificate) {
        let round = certificate.round;
        if let Some(known_certificate) = &self.leader_timeout {
            if known_certificate.round >= round {
                return;
            }
        }
        self.update_timeout(round);
        self.leader_timeout = Some(certificate);
    }

    /// Returns the public key of the block proposal's signer, if they are a valid owner and allowed
    /// to propose a block in the proposal's round.
    pub fn verify_owner(&self, proposal: &BlockProposal) -> Option<PublicKey> {
        let round = proposal.content.round.0;
        let height = proposal.content.block.height.0;
        let seed = round.rotate_left(32).wrapping_add(height);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let index = self.distribution.sample(&mut rng);
        let (owner, (key, _)) = self.owners.iter().nth(index)?;
        (*owner == proposal.owner).then_some(*key)
    }

    /// Returns the highest block we voted to confirm (or would have, if we are not a validator).
    fn locked_block(&self) -> Option<(&Block, RoundNumber)> {
        let locked = self.locked.as_ref()?;
        let block = &locked.value().executed_block()?.block;
        Some((block, locked.round))
    }
}

/// Chain manager information that is included in `ChainInfo` sent to clients, about chains
/// with multiple owners.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test"), derive(Eq, PartialEq))]
pub struct MultiOwnerFtManagerInfo {
    /// The co-owners of the chain.
    pub owners: HashMap<Owner, (PublicKey, u128)>,
    /// Latest authenticated block that we have received, if requested.
    pub requested_proposed: Option<BlockProposal>,
    /// Latest validated proposal that we have seen (and voted to confirm), if requested.
    pub requested_locked: Option<Certificate>,
    /// Latest vote we cast (either to validate or to confirm a block).
    pub pending: Option<LiteVote>,
    /// Latest timeout vote we cast.
    pub timeout_vote: Option<Vote>,
    /// The value we voted for, if requested.
    pub requested_pending_value: Option<HashedValue>,
    /// The current round.
    pub next_round: RoundNumber,
}

impl From<&MultiOwnerFtManager> for MultiOwnerFtManagerInfo {
    fn from(manager: &MultiOwnerFtManager) -> Self {
        MultiOwnerFtManagerInfo {
            owners: manager.owners.clone().into_iter().collect(),
            requested_proposed: None,
            requested_locked: None,
            pending: manager.pending.as_ref().map(|vote| vote.lite()),
            timeout_vote: manager.timeout_vote.clone(),
            requested_pending_value: None,
            next_round: manager.next_round(),
        }
    }
}

impl MultiOwnerFtManagerInfo {
    pub fn add_values(&mut self, manager: &MultiOwnerFtManager) {
        self.requested_proposed = manager.proposed.clone();
        self.requested_locked = manager.locked.clone();
        self.requested_pending_value = manager.pending.as_ref().map(|vote| vote.value.clone());
    }

    pub fn next_round(&self) -> RoundNumber {
        self.next_round
    }
}
