//! Peer-credential check for the loopback control plane (audit 2026-07 H1).
//!
//! Legion binds its dashboard/API to `127.0.0.1`, but a loopback TCP socket is
//! reachable by *every* local user — not just the one who launched Legion. So
//! the session cookie handed out by `GET /`, and therefore the whole privileged
//! (often root-level) API, was obtainable by any local account: loopback
//! reachability was being treated as equivalent to same-user. It is not.
//!
//! This module recovers the UID that owns the peer end of a loopback TCP
//! connection — on Linux, by matching the connection against `/proc/net/tcp`
//! and reading the owning UID column — so the server can refuse connections
//! from a *different* local user while still serving the human who started it.
//! That human is authorized even when Legion has self-elevated to root and the
//! browser still runs as the invoking user, via `PKEXEC_UID` / `SUDO_UID`.
//!
//! Scope: IPv4 loopback is fully covered (the default bind). IPv6 peers and
//! non-Linux platforms return [`PeerAuth::Unknown`] (fail-open — the session
//! token still gates `/api/*`); closing those is tracked as follow-up work.

use std::collections::HashSet;
use std::net::SocketAddr;
// `Ipv4Addr` is only referenced by the `/proc/net/tcp` parser, which is compiled
// on Linux / in tests only — keep the import on the same cfg to avoid an
// unused-import error on the Windows non-test build.
#[cfg(any(target_os = "linux", test))]
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuth {
    /// Peer belongs to an authorized (owning) user — serve it.
    Allowed,
    /// Peer is a different local user — refuse.
    Denied { uid: u32 },
    /// Peer identity could not be determined (IPv6 / unsupported OS / parse
    /// failure). Caller decides whether to fail open or closed.
    Unknown,
}

/// UIDs allowed to reach the control plane: root, the server's own UID, and the
/// invoking human user when Legion self-elevated (`PKEXEC_UID` / `SUDO_UID`).
pub fn authorized_uids() -> HashSet<u32> {
    let mut set = HashSet::new();
    set.insert(0); // root already owns the box
    if let Some(u) = self_uid() {
        set.insert(u);
    }
    for var in ["PKEXEC_UID", "SUDO_UID"] {
        if let Ok(v) = std::env::var(var) {
            if let Ok(u) = v.trim().parse::<u32>() {
                set.insert(u);
            }
        }
    }
    set
}

#[cfg(target_os = "linux")]
fn self_uid() -> Option<u32> {
    // `/proc/self` is owned by the process's UID — no FFI needed.
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

#[cfg(not(target_os = "linux"))]
fn self_uid() -> Option<u32> {
    None
}

/// Decide whether `peer` (the remote end of a connection to our `local` bound
/// address) belongs to an authorized user.
pub fn check(peer: SocketAddr, local: SocketAddr, authorized: &HashSet<u32>) -> PeerAuth {
    match peer_uid(peer, local) {
        Some(uid) if authorized.contains(&uid) => PeerAuth::Allowed,
        Some(uid) => PeerAuth::Denied { uid },
        None => PeerAuth::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    // Only IPv4 loopback is parsed here; IPv6 → Unknown (fail-open upstream).
    if !matches!(peer, SocketAddr::V4(_)) || !matches!(local, SocketAddr::V4(_)) {
        return None;
    }
    let data = std::fs::read_to_string("/proc/net/tcp").ok()?;
    find_uid_in_proc(&data, peer, local)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_peer: SocketAddr, _local: SocketAddr) -> Option<u32> {
    None
}

/// Pure core: scan `/proc/net/tcp` text for the socket whose local endpoint is
/// our `peer` and whose remote endpoint is our `local` bound address, and
/// return its owning UID. Split out so it is unit-testable without `/proc`.
///
/// `/proc/net/tcp` columns: `sl local_address rem_address st tx:rx tr:when
/// retrnsmt uid …`. From the *client's* row, `local_address` is our peer and
/// `rem_address` is our own bound address — matching both sides disambiguates a
/// reused ephemeral port.
#[cfg(any(target_os = "linux", test))]
fn find_uid_in_proc(data: &str, peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    for line in data.lines().skip(1) {
        let mut f = line.split_whitespace();
        let _sl = f.next()?;
        let local_hex = f.next()?; // client local  == our peer
        let rem_hex = f.next()?; // client remote == our local
        let _st = f.next()?;
        let _queues = f.next()?;
        let _tr = f.next()?;
        let _retrnsmt = f.next()?;
        let uid = f.next()?;

        let (Some(la), Some(ra)) = (parse_v4_hex(local_hex), parse_v4_hex(rem_hex)) else {
            continue;
        };
        if la == peer && ra == local {
            return uid.parse::<u32>().ok();
        }
    }
    None
}

/// Parse a `/proc/net/tcp` IPv4 endpoint `"0100007F:0CEA"` into a `SocketAddr`.
/// The address is written as little-endian words on LE hosts (Legion's targets),
/// so the four address bytes are reversed; the port is host-order hex.
#[cfg(any(target_os = "linux", test))]
fn parse_v4_hex(s: &str) -> Option<SocketAddr> {
    let (addr, port) = s.split_once(':')?;
    if addr.len() != 8 {
        return None;
    }
    let b0 = u8::from_str_radix(&addr[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&addr[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&addr[4..6], 16).ok()?;
    let b3 = u8::from_str_radix(&addr[6..8], 16).ok()?;
    let ip = Ipv4Addr::new(b3, b2, b1, b0);
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(SocketAddr::from((ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_endpoint() {
        // 0100007F = 127.0.0.1 (LE word order); 0CEA = 3306.
        let sa = parse_v4_hex("0100007F:0CEA").unwrap();
        assert_eq!(sa, "127.0.0.1:3306".parse().unwrap());
        // 8080 = 0x1F90, host-order.
        let sa = parse_v4_hex("0100007F:1F90").unwrap();
        assert_eq!(sa, "127.0.0.1:8080".parse().unwrap());
    }

    #[test]
    fn rejects_malformed_endpoint() {
        assert!(parse_v4_hex("nope").is_none());
        assert!(parse_v4_hex("0100007F").is_none());
        assert!(parse_v4_hex("01007F:1F90").is_none());
    }

    // A realistic table for a client at 127.0.0.1:54321 connecting to our
    // server at 127.0.0.1:3000. Three rows exist on the machine: the server's
    // listening socket and accepted socket (both owned by the elevated server,
    // uid 0) and the *client's* socket (local=54321, rem=3000, uid 1000). We
    // must read the client's uid (1000), not the server's — so giving them
    // different uids proves we match the right row.
    const PROC: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001 1 0000 100
   1: 0100007F:0BB8 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 10002 1 0000 100
   2: 0100007F:D431 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000  1000        0 10003 1 0000 100";

    fn peer() -> SocketAddr {
        // 0xD431 = 54321 (the client's ephemeral port)
        "127.0.0.1:54321".parse().unwrap()
    }
    fn local() -> SocketAddr {
        // 0x0BB8 = 3000 (our bound port)
        "127.0.0.1:3000".parse().unwrap()
    }

    #[test]
    fn finds_owning_uid_for_matching_connection() {
        assert_eq!(find_uid_in_proc(PROC, peer(), local()), Some(1000));
    }

    #[test]
    fn no_match_when_endpoints_differ() {
        let other: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_eq!(find_uid_in_proc(PROC, other, local()), None);
    }

    #[test]
    fn check_allows_authorized_and_denies_others() {
        let mut authorized = HashSet::new();
        authorized.insert(1000u32);
        // We can't fabricate /proc here, so exercise the decision directly via
        // the pure parser + set membership the way check() composes them.
        let uid = find_uid_in_proc(PROC, peer(), local());
        assert_eq!(uid, Some(1000));
        assert!(authorized.contains(&uid.unwrap()));

        let stranger = 4242u32;
        assert!(!authorized.contains(&stranger));
    }

    // End-to-end against the *real* /proc on this machine: open a genuine
    // loopback connection and confirm check() both allows the owning uid and
    // denies a set that excludes it. Proves the real-format parse + both
    // decision branches without needing a second user account.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_loopback_connection_is_classified() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::os::unix::fs::MetadataExt;

        let my_uid = std::fs::metadata("/proc/self").unwrap().uid();

        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        // Keep the client socket alive for the duration so the connection stays
        // ESTABLISHED and visible in /proc/net/tcp.
        let _client = TcpStream::connect(addr).unwrap();
        let (mut conn, _) = srv.accept().unwrap();
        // Don't block reading; we only need the connection to exist.
        conn.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 1];
        let _ = conn.read(&mut buf);

        let peer = conn.peer_addr().unwrap(); // the client's ephemeral endpoint
        let local = conn.local_addr().unwrap(); // our bound endpoint

        let mut ok = HashSet::new();
        ok.insert(my_uid);
        assert_eq!(check(peer, local, &ok), PeerAuth::Allowed);

        let mut stranger = HashSet::new();
        stranger.insert(my_uid.wrapping_add(1));
        assert_eq!(
            check(peer, local, &stranger),
            PeerAuth::Denied { uid: my_uid }
        );
    }
}
