//! Aggregated metrics plus the merge operation that makes them
//! parallelisable.

use std::collections::HashMap;

use crate::parser::parse_line;

/// All counters for a set of lines. Used at two scales:
/// * one per rayon *fold* task (a thread-local partial result), and
/// * one global accumulator that lives for the whole run.
///
/// Parallelism design: `Metrics` is a *commutative monoid*: `Default` is the
/// identity and `merge` is associative and commutative (it is just
/// addition). That is exactly what rayon's `fold` + `reduce` need, so
/// threads never share mutable state or take locks; each owns its own
/// `Metrics` and the results are combined afterwards.
#[derive(Debug, Default)]
pub struct Metrics {
    pub total_lines: u64,
    pub malformed_lines: u64,
    /// Lines the string splitter rejected but the regex rescued.
    pub regex_rescued: u64,
    pub status_counts: HashMap<u16, u64>,
    pub ip_counts: HashMap<String, u64>,
    pub endpoint_counts: HashMap<String, u64>,
}

/// Increment `map[key]` allocating a `String` only on first sight of a key.
///
/// `HashMap::entry` takes the key *by value*, which would force a
/// `to_owned()` on every call, even for keys already present. Doing
/// `get_mut` first means the hot path (key exists) allocates nothing.
fn bump(map: &mut HashMap<String, u64>, key: &str) {
    match map.get_mut(key) {
        Some(count) => *count += 1,
        None => {
            map.insert(key.to_owned(), 1);
        }
    }
}

impl Metrics {
    /// Parse one line and record it. `&mut self` is exclusive access, so no
    /// synchronisation is needed; rayon hands each task its own `Metrics`.
    pub fn record_line(&mut self, line: &str) {
        self.total_lines += 1;
        // `parsed` borrows `line`; it is dropped at the end of this scope,
        // after we have copied what we need (only into owned map keys).
        match parse_line(line) {
            Some(parsed) => {
                if parsed.via_fallback {
                    self.regex_rescued += 1;
                }
                *self.status_counts.entry(parsed.status).or_insert(0) += 1;
                bump(&mut self.ip_counts, parsed.ip);
                bump(&mut self.endpoint_counts, parsed.endpoint);
            }
            None => self.malformed_lines += 1,
        }
    }

    fn size_hint(&self) -> usize {
        self.ip_counts.len() + self.endpoint_counts.len()
    }

    /// Fold `other` into `self`. Takes `other` *by value*, so its `String`
    /// keys are moved into `self` rather than cloned.
    pub fn merge(&mut self, mut other: Metrics) {
        // Merge the smaller maps into the larger: cost is O(min(a, b))
        // instead of always O(other). Safe because merge is commutative.
        if other.size_hint() > self.size_hint() {
            std::mem::swap(self, &mut other);
        }
        self.total_lines += other.total_lines;
        self.malformed_lines += other.malformed_lines;
        self.regex_rescued += other.regex_rescued;
        merge_map(&mut self.status_counts, other.status_counts);
        merge_map(&mut self.ip_counts, other.ip_counts);
        merge_map(&mut self.endpoint_counts, other.endpoint_counts);
    }
}

fn merge_map<K: std::hash::Hash + Eq>(into: &mut HashMap<K, u64>, from: HashMap<K, u64>) {
    for (key, count) in from {
        *into.entry(key).or_insert(0) += count;
    }
}

/// The `n` largest entries, by count descending, ties broken by key so
/// output is deterministic regardless of thread scheduling / hash order.
pub fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<(&str, u64)> {
    let mut v: Vec<(&str, u64)> = map.iter().map(|(k, &c)| (k.as_str(), c)).collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ip: &str, path: &str, status: u16) -> String {
        format!(r#"{ip} - - [10/Oct/2000:13:55:36 -0700] "GET {path} HTTP/1.1" {status} 10"#)
    }

    #[test]
    fn records_and_counts_malformed() {
        let mut m = Metrics::default();
        m.record_line(&line("1.1.1.1", "/a", 200));
        m.record_line(&line("1.1.1.1", "/b", 404));
        m.record_line("garbage");
        assert_eq!((m.total_lines, m.malformed_lines), (3, 1));
        assert_eq!(m.ip_counts["1.1.1.1"], 2);
        assert_eq!(m.status_counts[&404], 1);
    }

    #[test]
    fn merge_is_order_independent() {
        let build = |lines: &[(&str, &str, u16)]| {
            let mut m = Metrics::default();
            for (ip, p, s) in lines {
                m.record_line(&line(ip, p, *s));
            }
            m
        };
        let a = || build(&[("1.1.1.1", "/a", 200), ("2.2.2.2", "/a", 200)]);
        let b = || build(&[("1.1.1.1", "/b", 500)]);

        let mut ab = a();
        ab.merge(b());
        let mut ba = b();
        ba.merge(a());

        assert_eq!(ab.total_lines, 3);
        assert_eq!(ab.ip_counts, ba.ip_counts);
        assert_eq!(ab.endpoint_counts, ba.endpoint_counts);
        assert_eq!(ab.status_counts, ba.status_counts);
    }

    #[test]
    fn top_n_orders_and_truncates() {
        let mut m = HashMap::new();
        for (k, c) in [("b", 5), ("a", 5), ("c", 9), ("d", 1)] {
            m.insert(k.to_string(), c);
        }
        assert_eq!(top_n(&m, 3), vec![("c", 9), ("a", 5), ("b", 5)]);
    }
}
