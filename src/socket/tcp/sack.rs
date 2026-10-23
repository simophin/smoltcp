//! Sender-side SACK scoreboard (RFC 6675).
//!
//! The scoreboard records which parts of the transmitted-but-unacknowledged
//! sequence space the peer has reported as received through SACK blocks. It
//! is bounded: at most [`MAX_RANGES`] sorted, disjoint ranges are kept. When
//! it is full, the information farthest from the cumulative ACK point is
//! forgotten. Forgetting a range can only cause data to be retransmitted
//! although the peer already has it; it never frees unacknowledged data or
//! prevents loss recovery, because every decision taken from the scoreboard
//! falls back to the cumulative acknowledgement.

use crate::wire::TcpSeqNumber;

/// Maximum number of SACKed ranges remembered per socket.
pub(super) const MAX_RANGES: usize = 32;

/// RFC 6675 `DupThresh`: SACKed segments above a sequence number that mark it lost.
pub(super) const DUP_THRESH: usize = 3;

/// A half-open SACKed range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Range {
    start: TcpSeqNumber,
    end: TcpSeqNumber,
}

impl Range {
    const EMPTY: Range = Range {
        start: TcpSeqNumber(0),
        end: TcpSeqNumber(0),
    };

    fn len(&self) -> usize {
        self.end - self.start
    }

    /// Octets of `self` inside `[from, to)`.
    fn overlap(&self, from: TcpSeqNumber, to: TcpSeqNumber) -> usize {
        let start = self.start.max(from);
        let end = self.end.min(to);
        if start < end { end - start } else { 0 }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct Scoreboard {
    /// Sorted ascending, pairwise disjoint and non-adjacent.
    ranges: [Range; MAX_RANGES],
    len: usize,
}

impl Scoreboard {
    pub(super) const fn new() -> Scoreboard {
        Scoreboard {
            ranges: [Range::EMPTY; MAX_RANGES],
            len: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.len = 0;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    fn ranges(&self) -> &[Range] {
        &self.ranges[..self.len]
    }

    /// Record that `[start, end)` was received, returning whether any octet in it
    /// was not already known to be SACKed. The caller validates the range: it must
    /// be non-empty and lie within the transmitted, unacknowledged sequence space.
    pub(super) fn insert(&mut self, start: TcpSeqNumber, end: TcpSeqNumber) -> bool {
        debug_assert!(start < end);

        // Find the ranges that overlap or touch the new one; they merge into one.
        let first = self
            .ranges()
            .iter()
            .position(|r| r.end >= start)
            .unwrap_or(self.len);
        let last = self.ranges()[first..]
            .iter()
            .position(|r| r.start > end)
            .map(|n| first + n)
            .unwrap_or(self.len);

        let known: usize = self.ranges()[first..last]
            .iter()
            .map(|r| r.overlap(start, end))
            .sum();
        let new_octets = (end - start) > known;

        if first == last {
            // No overlap: a brand-new island.
            if self.len == MAX_RANGES {
                // Full. Keep the ranges nearest the cumulative ACK: drop the
                // highest one, unless the newcomer would itself be the highest.
                if first == MAX_RANGES {
                    return new_octets;
                }
                self.len -= 1;
            }
            self.ranges.copy_within(first..self.len, first + 1);
            self.ranges[first] = Range { start, end };
            self.len += 1;
        } else {
            let merged = Range {
                start: start.min(self.ranges[first].start),
                end: end.max(self.ranges[last - 1].end),
            };
            self.ranges.copy_within(last..self.len, first + 1);
            self.len -= last - first - 1;
            self.ranges[first] = merged;
        }

        new_octets
    }

    /// Forget everything below the cumulative acknowledgement point `una`.
    pub(super) fn trim(&mut self, una: TcpSeqNumber) {
        let drop = self
            .ranges()
            .iter()
            .position(|r| r.end > una)
            .unwrap_or(self.len);
        self.ranges.copy_within(drop..self.len, 0);
        self.len -= drop;
        if self.len > 0 && self.ranges[0].start < una {
            self.ranges[0].start = una;
        }
    }

    /// The end of the highest SACKed range.
    pub(super) fn highest_sacked(&self) -> Option<TcpSeqNumber> {
        self.ranges().last().map(|r| r.end)
    }

    /// Whether `seq` is inside a SACKed range.
    pub(super) fn is_sacked(&self, seq: TcpSeqNumber) -> bool {
        self.ranges().iter().any(|r| r.start <= seq && seq < r.end)
    }

    /// Octets inside `[from, to)` that the peer has not reported as received.
    pub(super) fn unsacked_octets(&self, from: TcpSeqNumber, to: TcpSeqNumber) -> usize {
        if from >= to {
            return 0;
        }
        let sacked: usize = self.ranges().iter().map(|r| r.overlap(from, to)).sum();
        (to - from) - sacked
    }

    /// RFC 6675 `IsLost`, expressed as a boundary: every octet below the returned
    /// sequence number (and at or above `una`) is considered lost, because at least
    /// `DUP_THRESH` SACKed segments, or more than `(DUP_THRESH - 1) * mss` SACKed
    /// octets, lie above it. Returns `una` when nothing is lost.
    pub(super) fn lost_edge(&self, una: TcpSeqNumber, mss: usize) -> TcpSeqNumber {
        let mut octets_above = 0;
        for (blocks_above, range) in self.ranges().iter().rev().enumerate() {
            octets_above += range.len();
            if blocks_above + 1 >= DUP_THRESH || octets_above > (DUP_THRESH - 1) * mss {
                return range.start.max(una);
            }
        }
        una
    }

    /// The first unSACKed hole at or above `from`: its start and its end, where the
    /// end is the start of the next SACKed range, or `None` when nothing is SACKed
    /// above it.
    pub(super) fn next_hole(&self, from: TcpSeqNumber) -> (TcpSeqNumber, Option<TcpSeqNumber>) {
        let mut start = from;
        for range in self.ranges() {
            if range.end <= start {
                continue;
            }
            if range.start <= start {
                start = range.end;
                continue;
            }
            return (start, Some(range.start));
        }
        (start, None)
    }

    /// The end of the highest unSACKed octet below `high_data`, and the start of
    /// the hole it lies in, or `None` if everything up to `high_data` is SACKed.
    pub(super) fn highest_hole(
        &self,
        una: TcpSeqNumber,
        high_data: TcpSeqNumber,
    ) -> Option<(TcpSeqNumber, TcpSeqNumber)> {
        let mut end = high_data;
        let mut start = una;
        for range in self.ranges().iter().rev() {
            if range.start >= end {
                continue;
            }
            if range.end >= end {
                end = range.start;
                continue;
            }
            start = range.end;
            break;
        }
        if start < end {
            Some((start, end))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn seq(n: i32) -> TcpSeqNumber {
        TcpSeqNumber(n)
    }

    fn ranges(sb: &Scoreboard) -> std::vec::Vec<(i32, i32)> {
        sb.ranges().iter().map(|r| (r.start.0, r.end.0)).collect()
    }

    #[test]
    fn insert_sorts_merges_and_reports_new_octets() {
        let mut sb = Scoreboard::new();
        assert!(sb.insert(seq(300), seq(400)));
        assert!(sb.insert(seq(100), seq(200)));
        assert_eq!(ranges(&sb), [(100, 200), (300, 400)]);
        // Duplicate and subset blocks carry nothing new.
        assert!(!sb.insert(seq(100), seq(200)));
        assert!(!sb.insert(seq(320), seq(380)));
        // Overlapping block extends an island.
        assert!(sb.insert(seq(150), seq(250)));
        assert_eq!(ranges(&sb), [(100, 250), (300, 400)]);
        // Touching block bridges two islands into one.
        assert!(sb.insert(seq(250), seq(300)));
        assert_eq!(ranges(&sb), [(100, 400)]);
        // A block spanning several islands merges them all.
        sb.insert(seq(500), seq(600));
        sb.insert(seq(700), seq(800));
        assert!(sb.insert(seq(50), seq(750)));
        assert_eq!(ranges(&sb), [(50, 800)]);
    }

    #[test]
    fn trim_drops_and_clips() {
        let mut sb = Scoreboard::new();
        sb.insert(seq(100), seq(200));
        sb.insert(seq(300), seq(400));
        sb.insert(seq(500), seq(600));
        sb.trim(seq(350));
        assert_eq!(ranges(&sb), [(350, 400), (500, 600)]);
        sb.trim(seq(600));
        assert!(sb.is_empty());
    }

    #[test]
    fn capacity_keeps_the_ranges_nearest_the_ack_point() {
        let mut sb = Scoreboard::new();
        for i in 0..MAX_RANGES as i32 {
            assert!(sb.insert(seq(i * 100), seq(i * 100 + 50)));
        }
        assert_eq!(sb.len(), MAX_RANGES);
        // A new island above everything is forgotten but still counts as news.
        assert!(sb.insert(seq(10_000), seq(10_050)));
        assert_eq!(sb.len(), MAX_RANGES);
        assert_eq!(sb.highest_sacked(), Some(seq(3150)));
        // A new island below evicts the highest one.
        assert!(sb.insert(seq(-100), seq(-50)));
        assert_eq!(sb.len(), MAX_RANGES);
        assert_eq!(ranges(&sb)[0], (-100, -50));
        assert_eq!(sb.highest_sacked(), Some(seq(3050)));
        // Merging into an existing island never needs a slot.
        assert!(sb.insert(seq(3050), seq(3080)));
        assert_eq!(sb.len(), MAX_RANGES);
        assert_eq!(sb.highest_sacked(), Some(seq(3080)));
    }

    #[test]
    fn accounting_and_loss_detection() {
        let mut sb = Scoreboard::new();
        let una = seq(0);
        assert_eq!(sb.lost_edge(una, 100), una);
        sb.insert(seq(100), seq(200));
        assert_eq!(sb.unsacked_octets(seq(0), seq(300)), 200);
        assert!(sb.is_sacked(seq(150)));
        assert!(!sb.is_sacked(seq(200)));
        // One block of one segment: nothing is lost yet.
        assert_eq!(sb.lost_edge(una, 100), una);
        sb.insert(seq(300), seq(400));
        assert_eq!(sb.lost_edge(una, 100), una);
        // Three discontiguous blocks: everything below the lowest one is lost.
        sb.insert(seq(500), seq(600));
        assert_eq!(sb.lost_edge(una, 100), seq(100));
        // More than 2 MSS SACKed in one block also marks the data below as lost.
        let mut sb = Scoreboard::new();
        sb.insert(seq(100), seq(300));
        assert_eq!(sb.lost_edge(una, 100), una);
        sb.insert(seq(100), seq(301));
        assert_eq!(sb.lost_edge(una, 100), seq(100));
        assert_eq!(sb.next_hole(seq(0)), (seq(0), Some(seq(100))));
        assert_eq!(sb.next_hole(seq(150)), (seq(301), None));
        assert_eq!(sb.highest_hole(una, seq(500)), Some((seq(301), seq(500))));
        assert_eq!(sb.highest_hole(una, seq(301)), Some((seq(0), seq(100))));
        assert_eq!(sb.highest_hole(seq(100), seq(301)), None);
    }

    #[test]
    fn works_across_sequence_wrap() {
        let mut sb = Scoreboard::new();
        let base = seq(i32::MAX - 150);
        sb.insert(base + 100, base + 200);
        sb.insert(base + 300, base + 400);
        assert!(sb.insert(base + 200, base + 300));
        assert_eq!(sb.unsacked_octets(base, base + 500), 200);
        assert_eq!(sb.lost_edge(base, 100), base + 100);
        assert_eq!(sb.next_hole(base + 150), (base + 400, None));
        sb.trim(base + 350);
        assert_eq!(sb.unsacked_octets(base + 350, base + 500), 100);
    }
}
