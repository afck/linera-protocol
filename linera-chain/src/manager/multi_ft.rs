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
    data_types::RoundNumber,
    ensure,
    identifiers::Owner,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use rand_distr::{Distribution, WeightedAliasIndex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::error;

/// The specific state of a chain with multiple owners some of which are potentially faulty.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiOwnerFtManager {
    /// The co-owners of the chain, with their weights.
    pub owners: BTreeMap<Owner, (PublicKey, u128)>,
    /// The probability distribution for choosing a round leader.
    pub distribution: WeightedAliasIndex<u128>,
    /// Latest authenticated block that we have received.
    pub proposed: Option<BlockProposal>,
    /// Latest validated proposal that we have seen (and voted to confirm).
    pub locked: Option<Certificate>,
    /// Latest proposal that we have voted on (either to validate or to confirm it).
    pub pending: Option<Vote>,
}

impl MultiOwnerFtManager {
    pub fn new(owners: impl IntoIterator<Item = (Owner, (PublicKey, u128))>) -> Self {
        let owners: BTreeMap<Owner, (PublicKey, u128)> = owners.into_iter().collect();
        let weights = owners.values().map(|(_, weight)| *weight).collect();
        let distribution = WeightedAliasIndex::new(weights)
            .expect("TODO: return error if weight sum is 0 or > u128::MAX.");

        MultiOwnerFtManager {
            owners,
            distribution,
            proposed: None,
            locked: None,
            pending: None,
        }
    }

    pub fn round(&self) -> RoundNumber {
        let mut current_round = RoundNumber::default();
        if let Some(proposal) = &self.proposed {
            if current_round < proposal.content.round {
                current_round = proposal.content.round;
            }
        }
        if let Some(Certificate { round, .. }) = &self.locked {
            if current_round < *round {
                current_round = *round;
            }
        }
        current_round
    }

    pub fn pending(&self) -> Option<&Vote> {
        self.pending.as_ref()
    }

    /// Verify the safety of the block w.r.t. voting rules.
    pub fn check_proposed_block(
        &self,
        new_block: &Block,
        new_round: RoundNumber,
    ) -> Result<Outcome, ChainError> {
        if let Some(proposal) = &self.proposed {
            if proposal.content.block == *new_block && proposal.content.round == new_round {
                return Ok(Outcome::Skip);
            }
            if new_round <= proposal.content.round {
                return Err(ChainError::InsufficientRound(proposal.content.round));
            }
        }
        if let Some(Certificate { round, value, .. }) = &self.locked {
            if let CertificateValue::ValidatedBlock {
                executed_block: ExecutedBlock { block, .. },
            } = value.inner()
            {
                ensure!(new_round > *round, ChainError::InsufficientRound(*round));
                ensure!(
                    *new_block == *block,
                    ChainError::HasLockedBlock(block.height, *round)
                );
            }
        }
        Ok(Outcome::Accept)
    }

    pub fn check_validated_block(
        &self,
        new_block: &Block,
        new_round: RoundNumber,
    ) -> Result<Outcome, ChainError> {
        if let Some(Vote { value, round, .. }) = &self.pending {
            match value.inner() {
                CertificateValue::ConfirmedBlock { executed_block } => {
                    if executed_block.block == *new_block && *round == new_round {
                        return Ok(Outcome::Skip);
                    }
                }
                CertificateValue::ValidatedBlock { .. } => ensure!(
                    new_round >= *round,
                    ChainError::InsufficientRound(round.try_sub_one().unwrap())
                ),
                value => {
                    let msg = format!("Unexpected value: {:?}", value);
                    return Err(ChainError::InternalError(msg));
                }
            }
        }
        if let Some(Certificate { round, .. }) = &self.locked {
            ensure!(
                new_round >= *round,
                ChainError::InsufficientRound(round.try_sub_one().unwrap())
            );
        }
        Ok(Outcome::Accept)
    }

    pub fn create_vote(
        &mut self,
        proposal: BlockProposal,
        messages: Vec<OutgoingMessage>,
        state_hash: CryptoHash,
        key_pair: Option<&KeyPair>,
    ) {
        // Record the proposed block. This is important to keep track of rounds
        // for non-voting nodes.
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
        // Record validity certificate. This is important to keep track of rounds
        // for non-voting nodes.
        let Some(value) = certificate.value.clone().into_confirmed() else {
            error!("Unexpected value for final vote: {:?}", certificate.value());
            return;
        };
        let round = certificate.round;
        self.locked = Some(certificate);
        if let Some(key_pair) = key_pair {
            // Vote to confirm.
            let vote = Vote::new(value, round, key_pair);
            // Ok to overwrite validation votes with confirmation votes at equal or higher round.
            self.pending = Some(vote);
        }
    }

    pub fn verify_owner(&self, proposal: &BlockProposal) -> Option<PublicKey> {
        let round = proposal.content.round.0;
        let height = proposal.content.block.height.0;
        let seed = round.rotate_left(32).wrapping_add(height);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let index = self.distribution.sample(&mut rng);
        let (owner, (key, _)) = self.owners.iter().nth(index)?;
        (*owner == proposal.owner).then_some(*key)
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
    /// The value we voted for, if requested.
    pub requested_pending_value: Option<HashedValue>,
    /// The current round.
    pub round: RoundNumber,
}

impl From<&MultiOwnerFtManager> for MultiOwnerFtManagerInfo {
    fn from(manager: &MultiOwnerFtManager) -> Self {
        MultiOwnerFtManagerInfo {
            owners: manager.owners.clone().into_iter().collect(),
            requested_proposed: None,
            requested_locked: None,
            pending: manager.pending.as_ref().map(|vote| vote.lite()),
            requested_pending_value: None,
            round: manager.round(),
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
        self.round.try_add_one().unwrap_or(self.round)
    }
}
