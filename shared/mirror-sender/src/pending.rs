//! Admission policy for connections still in the handshake (pre-auth).
//!
//! Policy, applied when a new connection from `ip` arrives:
//! 1. If `ip` already has `per_ip` pending handshakes, its oldest one is
//!    evicted (newest wins per host, like authenticated clients).
//! 2. Otherwise, if `max` handshakes are pending in total, the oldest
//!    pending handshake of the busiest peer is evicted (IPv6: busiest /64,
//!    then its busiest address; ties: the oldest pending handshake), see
//!    below.
//! 3. The new connection is always admitted.
//!
//! With `per_ip < max`, a host can hold at most `per_ip` slots, so a client
//! on another IP always gets a slot. A client outside the flooder's IPv6 /64
//! is never the eviction victim while the flooding host holds more pending
//! handshakes than it does; one inside it is spared only while the flooder
//! reuses an address (rule 2 then picks the busiest exact address of the
//! group). A flood from many distinct IPs (≥ `max`) can still evict it;
//! that is the best a pre-auth server can do.
//!
//! Rule 1 counts exact addresses: hosts of one IPv6 LAN share a /64, so
//! grouping there would let one LAN host evict another's handshakes. Rule 2
//! groups IPv6 peers by /64 when choosing the victim group: one host can
//! pick any of the 2^64 addresses of its subnet to stay under rule 1, so its
//! subnet is what makes it the busiest. Within that group the victim is the
//! oldest handshake of its busiest exact address.

use std::collections::VecDeque;
use std::net::IpAddr;

#[derive(Debug)]
pub(crate) struct PendingSet {
    per_ip: usize,
    max: usize,
    /// (connection id, canonical peer IP), oldest first.
    entries: VecDeque<(u64, IpAddr)>,
}

impl PendingSet {
    pub(crate) fn new(max: usize, per_ip: usize) -> Self {
        PendingSet {
            per_ip: per_ip.max(1),
            max: max.max(1),
            entries: VecDeque::new(),
        }
    }

    /// The unit the global-cap victim choice counts: the address, or its
    /// /64 for IPv6.
    fn group(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(a) => {
                let s = a.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            v4 => v4,
        }
    }

    fn count(&self, ip: IpAddr) -> usize {
        self.entries.iter().filter(|e| e.1 == ip).count()
    }

    /// Admit connection `id` from `ip`. Returns the id of the pending
    /// handshake that must be closed to make room, if any (already removed).
    pub(crate) fn admit(&mut self, id: u64, ip: IpAddr) -> Option<u64> {
        let ip = ip.to_canonical();
        let victim = if self.count(ip) >= self.per_ip {
            self.entries.iter().position(|e| e.1 == ip)
        } else if self.entries.len() >= self.max {
            // The busiest group (ties: the one whose pending handshake is
            // oldest); within it, the oldest entry of its busiest exact
            // address, so a legit host sharing the flooder's /64 is spared
            // while the flooder reuses addresses. When every address in the
            // group is tied (one per address), that is the group's oldest.
            let busiest = |key: fn(IpAddr) -> IpAddr, within: Option<IpAddr>| {
                let mut best: Option<(usize, usize)> = None;
                for (i, e) in self.entries.iter().enumerate() {
                    if within.is_some_and(|g| Self::group(e.1) != g) {
                        continue;
                    }
                    let k = key(e.1);
                    let n = self.entries.iter().filter(|o| key(o.1) == k).count();
                    if best.is_none_or(|(_, bn)| n > bn) {
                        best = Some((i, n));
                    }
                }
                best.map(|(i, _)| i)
            };
            busiest(Self::group, None)
                .and_then(|i| busiest(|ip| ip, Some(Self::group(self.entries[i].1))))
        } else {
            None
        };
        let victim = victim.and_then(|i| self.entries.remove(i)).map(|e| e.0);
        self.entries.push_back((id, ip));
        victim
    }

    /// Remove `id`. False if it was not pending (e.g. already evicted).
    pub(crate) fn remove(&mut self, id: u64) -> bool {
        match self.entries.iter().position(|e| e.0 == id) {
            Some(i) => {
                self.entries.remove(i);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admits_without_eviction_under_caps() {
        let mut p = PendingSet::new(4, 2);
        assert_eq!(p.admit(1, ip("10.0.0.1")), None);
        assert_eq!(p.admit(2, ip("10.0.0.1")), None);
        assert_eq!(p.admit(3, ip("10.0.0.2")), None);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn per_ip_cap_evicts_that_ips_oldest() {
        let mut p = PendingSet::new(4, 2);
        p.admit(1, ip("10.0.0.9")); // attacker
        p.admit(2, ip("10.0.0.5")); // legit receiver
        p.admit(3, ip("10.0.0.9"));
        // The attacker keeps reconnecting: only its own sockets are evicted.
        assert_eq!(p.admit(4, ip("10.0.0.9")), Some(1));
        assert_eq!(p.admit(5, ip("10.0.0.9")), Some(3));
        assert_eq!(p.admit(6, ip("10.0.0.9")), Some(4));
        assert!(p.remove(2), "legit handshake still pending");
    }

    #[test]
    fn global_cap_evicts_from_the_busiest_ip() {
        let mut p = PendingSet::new(4, 3);
        p.admit(1, ip("10.0.0.5")); // legit, oldest overall
        p.admit(2, ip("10.0.0.9"));
        p.admit(3, ip("10.0.0.9"));
        p.admit(4, ip("10.0.0.7"));
        // Full: evict the oldest of the busiest IP (.9), not the oldest overall.
        assert_eq!(p.admit(5, ip("10.0.0.8")), Some(2));
        assert_eq!(p.len(), 4);
        // Now every IP has one pending: the oldest overall goes.
        assert_eq!(p.admit(6, ip("10.0.0.6")), Some(1));
    }

    #[test]
    fn ipv4_mapped_counts_as_ipv4() {
        let mut p = PendingSet::new(8, 1);
        p.admit(1, ip("192.168.1.2"));
        assert_eq!(p.admit(2, ip("::ffff:192.168.1.2")), Some(1));
    }

    #[test]
    fn ipv6_per_ip_cap_counts_exact_addresses() {
        let mut p = PendingSet::new(8, 1);
        p.admit(1, ip("fd00:1:2:3::1"));
        // Another host on the same LAN /64 does not evict the first one.
        assert_eq!(p.admit(2, ip("fd00:1:2:3::2")), None);
        // The same address does.
        assert_eq!(p.admit(3, ip("fd00:1:2:3::1")), Some(1));
    }

    #[test]
    fn ipv6_global_cap_groups_by_64() {
        let mut p = PendingSet::new(4, 2);
        p.admit(1, ip("fd00:1:2:4::1")); // legit, oldest overall
                                         // One host rotating through its /64 (each address under per_ip).
        p.admit(2, ip("fd00:1:2:3::a"));
        p.admit(3, ip("fd00:1:2:3::b"));
        p.admit(4, ip("fd00:1:2:3::c"));
        // Full: the /64 with the most pending handshakes loses its oldest.
        assert_eq!(p.admit(5, ip("10.0.0.1")), Some(2));
        assert!(p.remove(1), "legit handshake still pending");
    }

    #[test]
    fn ipv6_global_cap_spares_a_legit_host_in_the_flooders_64() {
        let mut p = PendingSet::new(4, 2);
        p.admit(1, ip("fd00:1:2:3::100")); // legit, same /64 as the flooder
        p.admit(2, ip("fd00:1:2:3::a"));
        p.admit(3, ip("fd00:1:2:3::a"));
        p.admit(4, ip("fd00:1:2:3::b"));
        // Full: the busiest exact address (::a) loses its oldest, not ::100.
        assert_eq!(p.admit(5, ip("fd00:1:2:3::b")), Some(2));
        assert!(p.remove(1), "legit handshake still pending");
    }

    #[test]
    fn remove_is_idempotent() {
        let mut p = PendingSet::new(1, 1);
        p.admit(1, ip("10.0.0.1"));
        assert_eq!(p.admit(2, ip("10.0.0.2")), Some(1));
        assert!(!p.remove(1), "evicted entry is gone");
        assert!(p.remove(2));
        assert!(!p.remove(2));
    }
}
