// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Human-readable diffs between two [`BlockExecutionOutcome`]s, for diagnosing
//! mismatches between a computed and a certified outcome.

use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
};

use super::BlockExecutionOutcome;

/// Number of matching characters kept around a differing region as context.
const DIFF_CONTEXT: usize = 16;
/// Maximum number of characters shown for each side of a differing region.
const MAX_DIFF_REGION: usize = 256;

/// Returns a human-readable description of how `outcome` differs from `other`.
///
/// `self_label` and `other_label` name the two outcomes in the output. The first line
/// is a single-line summary listing the names of the differing fields, so it stays
/// readable on its own in log viewers that show lines in reverse order.
///
/// The following lines locate each difference down to the individual element (e.g.
/// `messages[2][5]`) and, for the differing values, elide the leading and trailing
/// parts that match in both, truncating the differing region if it is very long. This
/// keeps the output small even when only a small part of a large value differs.
pub(super) fn describe(
    outcome: &BlockExecutionOutcome,
    other: &BlockExecutionOutcome,
    self_label: &str,
    other_label: &str,
) -> String {
    let mut writer = Writer {
        self_label,
        other_label,
        differing: Vec::new(),
        details: String::new(),
    };
    writer.seq2("messages", &outcome.messages, &other.messages);
    writer.map(
        "previous_message_blocks",
        &outcome.previous_message_blocks,
        &other.previous_message_blocks,
    );
    writer.map(
        "previous_event_blocks",
        &outcome.previous_event_blocks,
        &other.previous_event_blocks,
    );
    writer.value("state_hash", &outcome.state_hash, &other.state_hash);
    writer.seq2(
        "oracle_responses",
        &outcome.oracle_responses,
        &other.oracle_responses,
    );
    writer.seq2("events", &outcome.events, &other.events);
    writer.seq2("blobs", &outcome.blobs, &other.blobs);
    writer.seq(
        "operation_results",
        &outcome.operation_results,
        &other.operation_results,
    );
    writer.finish()
}

/// Accumulates the summary of differing field names and the detailed per-element diffs.
struct Writer<'a> {
    self_label: &'a str,
    other_label: &'a str,
    /// The names of the top-level fields that differ, for the summary line.
    differing: Vec<&'a str>,
    /// The detailed, per-element diffs.
    details: String,
}

impl<'a> Writer<'a> {
    /// Compares a scalar field, recording it if it differs.
    fn value<T: fmt::Debug + PartialEq>(&mut self, name: &'a str, a: &T, b: &T) {
        if a != b {
            self.differing.push(name);
            self.push_leaf(name, a, b);
        }
    }

    /// Compares a sequence field, recording it and the differing indices if it differs.
    fn seq<T: fmt::Debug + PartialEq>(&mut self, name: &'a str, a: &[T], b: &[T]) {
        if a != b {
            self.differing.push(name);
            self.describe_seq(name, a, b);
        }
    }

    /// Compares a sequence-of-sequences field (e.g. per-transaction messages),
    /// recording it and locating differences down to `name[i][j]`.
    fn seq2<T: fmt::Debug + PartialEq>(&mut self, name: &'a str, a: &[Vec<T>], b: &[Vec<T>]) {
        if a != b {
            self.differing.push(name);
            self.note_len(name, a.len(), b.len());
            for i in 0..a.len().min(b.len()) {
                if a[i] != b[i] {
                    self.describe_seq(&format!("{name}[{i}]"), &a[i], &b[i]);
                }
            }
        }
    }

    /// Compares a map field, recording it and the keys that differ or are missing.
    fn map<K: fmt::Debug + Ord, V: fmt::Debug + PartialEq>(
        &mut self,
        name: &'a str,
        a: &BTreeMap<K, V>,
        b: &BTreeMap<K, V>,
    ) {
        if a == b {
            return;
        }
        self.differing.push(name);
        for (key, value) in a {
            match b.get(key) {
                None => write!(
                    self.details,
                    "\n\n{name}[{key:?}]: only in {}",
                    self.self_label
                )
                .unwrap(),
                Some(other) if value != other => {
                    self.push_leaf(&format!("{name}[{key:?}]"), value, other)
                }
                Some(_) => {}
            }
        }
        for key in b.keys() {
            if !a.contains_key(key) {
                write!(
                    self.details,
                    "\n\n{name}[{key:?}]: only in {}",
                    self.other_label
                )
                .unwrap();
            }
        }
    }

    /// Notes a length mismatch for the sequence at `path`, then diffs each differing
    /// element up to the shorter length.
    fn describe_seq<T: fmt::Debug + PartialEq>(&mut self, path: &str, a: &[T], b: &[T]) {
        self.note_len(path, a.len(), b.len());
        for i in 0..a.len().min(b.len()) {
            if a[i] != b[i] {
                self.push_leaf(&format!("{path}[{i}]"), &a[i], &b[i]);
            }
        }
    }

    fn note_len(&mut self, path: &str, a: usize, b: usize) {
        if a != b {
            write!(
                self.details,
                "\n\n{path}: length differs ({} = {a}, {} = {b})",
                self.self_label, self.other_label
            )
            .unwrap();
        }
    }

    /// Appends a compact diff of the debug representations of two differing values.
    fn push_leaf<T: fmt::Debug>(&mut self, path: &str, a: &T, b: &T) {
        let mine = format!("{a:#?}");
        let theirs = format!("{b:#?}");
        if mine == theirs {
            // The values differ but their `Debug` output does not, e.g. because
            // `hex_debug` elides the middle of a long byte vector.
            write!(
                self.details,
                "\n\n{path}: values differ but their debug representations are identical \
                 (likely elided binary data)"
            )
            .unwrap();
            return;
        }
        let body = compact_value_diff(&mine, &theirs, self.self_label, self.other_label);
        write!(self.details, "\n\n{path}:{body}").unwrap();
    }

    fn finish(self) -> String {
        format!("differing fields: {:?}{}", self.differing, self.details)
    }
}

/// Diffs two debug strings, showing only the differing middle of each (with a little
/// matching context) and truncating that middle if it is very long.
fn compact_value_diff(a: &str, b: &str, self_label: &str, other_label: &str) -> String {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let lead = lead_context(&a[..prefix]);
    let trail = trail_context(&a[a.len() - suffix..]);
    let mine = cap_region(&a[prefix..a.len() - suffix]);
    let theirs = cap_region(&b[prefix..b.len() - suffix]);
    format!("\n  {self_label}: {lead}{mine}{trail}\n  {other_label}: {lead}{theirs}{trail}")
}

/// Renders the tail of the matching prefix, eliding all but the last [`DIFF_CONTEXT`]
/// characters.
fn lead_context(prefix: &[char]) -> String {
    if prefix.len() <= DIFF_CONTEXT {
        prefix.iter().collect()
    } else {
        format!(
            "…{}",
            prefix[prefix.len() - DIFF_CONTEXT..]
                .iter()
                .collect::<String>()
        )
    }
}

/// Renders the head of the matching suffix, eliding all but the first [`DIFF_CONTEXT`]
/// characters.
fn trail_context(suffix: &[char]) -> String {
    if suffix.len() <= DIFF_CONTEXT {
        suffix.iter().collect()
    } else {
        format!("{}…", suffix[..DIFF_CONTEXT].iter().collect::<String>())
    }
}

/// Renders a differing region, truncating its middle if it exceeds [`MAX_DIFF_REGION`].
fn cap_region(region: &[char]) -> String {
    if region.len() <= MAX_DIFF_REGION {
        return region.iter().collect();
    }
    let head: String = region[..MAX_DIFF_REGION / 2].iter().collect();
    let tail: String = region[region.len() - MAX_DIFF_REGION / 2..]
        .iter()
        .collect();
    let elided = region.len() - MAX_DIFF_REGION;
    format!("{head}…[{elided} chars]…{tail}")
}

#[cfg(test)]
mod tests {
    use linera_base::crypto::{CryptoHash, TestString};

    use crate::data_types::{BlockExecutionOutcome, OperationResult};

    #[test]
    fn lists_only_differing_fields() {
        let computed = BlockExecutionOutcome {
            state_hash: CryptoHash::new(&TestString::new("a")),
            ..BlockExecutionOutcome::default()
        };
        let submitted = BlockExecutionOutcome {
            state_hash: CryptoHash::new(&TestString::new("b")),
            ..BlockExecutionOutcome::default()
        };

        let diff = computed.diff(&submitted, "computed", "submitted");
        // The single-line summary names only the field that differs, and stays readable
        // on its own even when a log viewer shows lines in reverse order.
        assert_eq!(
            diff.lines().next().unwrap(),
            "differing fields: [\"state_hash\"]"
        );
        assert!(diff.contains("\n\nstate_hash:"));
        assert!(!diff.contains("operation_results"));
    }

    #[test]
    fn equal_outcomes_have_no_differing_fields() {
        let outcome = BlockExecutionOutcome::default();
        assert_eq!(
            outcome.diff(&outcome, "computed", "submitted"),
            "differing fields: []"
        );
    }

    #[test]
    fn locates_differing_element_and_elides_matching_bytes() {
        // Short enough that `hex_debug` shows the full hex, with a single differing byte
        // in the middle.
        let mut computed_bytes = vec![0xab; 30];
        let mut submitted_bytes = computed_bytes.clone();
        computed_bytes[15] = 0x1c;
        submitted_bytes[15] = 0x2d;
        let computed = BlockExecutionOutcome {
            operation_results: vec![
                OperationResult(vec![0xee; 2]),
                OperationResult(computed_bytes),
            ],
            ..BlockExecutionOutcome::default()
        };
        let submitted = BlockExecutionOutcome {
            operation_results: vec![
                OperationResult(vec![0xee; 2]),
                OperationResult(submitted_bytes),
            ],
            ..BlockExecutionOutcome::default()
        };

        let diff = computed.diff(&submitted, "computed", "submitted");
        assert_eq!(
            diff.lines().next().unwrap(),
            "differing fields: [\"operation_results\"]"
        );
        // Only the differing element is reported, located by index.
        assert!(diff.contains("\n\noperation_results[1]:"));
        assert!(!diff.contains("operation_results[0]"));
        // Matching bytes are elided, leaving the differing bytes of each side.
        assert!(diff.contains('…'));
        assert!(diff.contains("1c"));
        assert!(diff.contains("2d"));
        assert!(diff.lines().all(|line| line.chars().count() < 120));
    }

    #[test]
    fn notes_when_difference_is_elided_by_debug() {
        // `hex_debug` elides the middle of long byte vectors, so two values differing
        // only there have identical debug output.
        let mut submitted_bytes = vec![0xab; 100];
        submitted_bytes[50] = 0x22;
        let computed = BlockExecutionOutcome {
            operation_results: vec![OperationResult(vec![0xab; 100])],
            ..BlockExecutionOutcome::default()
        };
        let submitted = BlockExecutionOutcome {
            operation_results: vec![OperationResult(submitted_bytes)],
            ..BlockExecutionOutcome::default()
        };

        let diff = computed.diff(&submitted, "computed", "submitted");
        assert!(diff.contains("operation_results[0]: values differ but their debug"));
    }

    #[test]
    fn reports_length_mismatch() {
        let computed = BlockExecutionOutcome {
            operation_results: vec![OperationResult(vec![1])],
            ..BlockExecutionOutcome::default()
        };
        let submitted = BlockExecutionOutcome::default();

        let diff = computed.diff(&submitted, "computed", "submitted");
        assert!(diff.contains("operation_results: length differs (computed = 1, submitted = 0)"));
    }
}
