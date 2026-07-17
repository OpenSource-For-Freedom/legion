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
//! Scope: IPv4 loopback is covered on Linux (`/proc/net/tcp`) and Windows (the
//! owning process of the peer socket via `netstat -ano`, whose **SID** is then
//! compared to our own). IPv6 peers and other platforms (macOS) return
//! [`PeerAuth::Unknown`] (fail-open — the session token still gates `/api/*`).
//!
//! Identity is compared by SID, never by user name: two domains can each have an
//! `alice`, and a name comparison would authorize both. Every parser here is a
//! pure function over captured output so the Windows path is exercised by tests
//! on **any** platform — it previously had none, being compiled by Windows CI
//! and never run, which is how a hardcoded CSV column index survived.

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

// macOS / other Unix: peer identity not recovered (fail-open upstream).
#[cfg(not(any(target_os = "linux", windows)))]
fn peer_uid(_peer: SocketAddr, _local: SocketAddr) -> Option<u32> {
    None
}

// Windows: no numeric UID, so map the owning process of the peer socket to a
// same-user decision and encode it in the u32 the shared `check()` expects — `0`
// (always in the authorized set) for the current user, a non-authorized sentinel
// for a different local user, `None` when it can't be determined (fail-open,
// exactly as before). Cached per connection so the lookups stay off the
// per-request hot path.
//
// An undeterminable peer stays fail-open deliberately: the session token still
// gates every `/api/*` route, and failing closed here would lock the legitimate
// operator out of their own dashboard on any lookup hiccup. What changed is that
// a *wrong* answer is no longer possible from a name collision — the comparison
// is SID-based, so the fail-open path is now genuinely rare rather than routine
// on a localized host.
#[cfg(windows)]
fn peer_uid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<SocketAddr, Option<u32>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(c) = cache.lock() {
        if let Some(v) = c.get(&peer).copied() {
            return v;
        }
    }
    let decision = windows_same_user(peer, local).map(|same| if same { 0 } else { 1 });
    if let Ok(mut c) = cache.lock() {
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(peer, decision);
    }
    decision
}

#[cfg(windows)]
fn windows_same_user(peer: SocketAddr, local: SocketAddr) -> Option<bool> {
    let pid = windows_owning_pid(peer, local)?;
    let (owner_sid, my_sid) = windows_sid_pair(pid)?;
    Some(sids_match(&owner_sid, &my_sid))
}

/// Find the PID owning the *client* end of the loopback connection: the
/// `netstat -ano` row whose Local Address == our peer and Foreign Address == our
/// bound address.
#[cfg(windows)]
fn windows_owning_pid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let out = std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_netstat_owning_pid(&text, peer, local)
}

/// Pure core of [`windows_owning_pid`], so the row matching is unit-testable off
/// Windows. Only the protocol, the two endpoints and the PID are read — never the
/// connection-state column, which is localized.
#[cfg(any(windows, test))]
fn parse_netstat_owning_pid(text: &str, peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let peer_s = peer.to_string();
    let local_s = local.to_string();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 5
            && f[0].eq_ignore_ascii_case("TCP")
            && f[1] == peer_s.as_str()
            && f[2] == local_s.as_str()
        {
            return f[4].parse::<u32>().ok();
        }
    }
    None
}

/// `(owner_sid_of_pid, our_own_user_sid)`.
///
/// Replaces reading the localized `User Name` column out of `tasklist /v` CSV by
/// a hardcoded index, which was wrong twice over: the column moves on a
/// localized Windows (silently yielding some other field), and comparing bare
/// user *names* makes `CORP\alice` and `ATTACKER\alice` equal — authorizing a
/// different principal. A SID is unique and locale-independent.
///
/// Both SIDs come from one PowerShell call, halving the process spawns per new
/// peer as well. UAC elevation preserves the user SID, so an elevated Legion
/// still matches the browser running as the same human.
#[cfg(windows)]
fn windows_sid_pair(pid: u32) -> Option<(String, String)> {
    let ps = format!(
        "$ErrorActionPreference='Stop';\
         $p=Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\";\
         $o=(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid;\
         $m=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;\
         Write-Output $o; Write-Output $m"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .ok()?;
    parse_sid_pair(&String::from_utf8_lossy(&out.stdout))
}

/// Pure core of [`windows_sid_pair`]: two non-empty SID lines, owner first.
#[cfg(any(windows, test))]
fn parse_sid_pair(stdout: &str) -> Option<(String, String)> {
    let mut lines = stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    let owner = lines.next()?.to_string();
    let me = lines.next()?.to_string();
    // Anything that is not a SID means the lookup failed (an error string, a
    // localized message). Treating it as an identity would be worse than
    // reporting "unknown".
    (looks_like_sid(&owner) && looks_like_sid(&me)).then_some((owner, me))
}

/// A Windows security identifier: `S-1-...`, digits and dashes only.
#[cfg(any(windows, test))]
fn looks_like_sid(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next() == Some("S")
        && parts.next() == Some("1")
        && s.len() > 6
        && s.split('-')
            .skip(2)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether the peer process belongs to the same principal as this process.
///
/// Exact SID equality, never a name comparison: two different domains can each
/// have an `alice`, and the old name check authorized both.
#[cfg(any(windows, test))]
fn sids_match(owner: &str, me: &str) -> bool {
    !owner.is_empty() && !me.is_empty() && owner.eq_ignore_ascii_case(me)
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

    // ── Windows peer-credential core ─────────────────────────────────────────
    // These run on every platform on purpose. The Windows path previously had
    // zero test coverage — it was compiled by Windows CI and never executed, so
    // a hardcoded CSV column index and a name-based identity comparison shipped
    // unnoticed. Keeping the parsers pure is what makes them testable here.

    #[test]
    fn sid_comparison_does_not_confuse_different_principals() {
        let alice_corp = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        let alice_attacker = "S-1-5-21-9999999999-8888888888-7777777777-1001";
        assert!(sids_match(alice_corp, alice_corp));
        // The regression: the old check compared bare user names, so CORP\alice
        // and ATTACKER\alice were "the same user" and the attacker was served a
        // session cookie for the privileged API.
        assert!(
            !sids_match(alice_corp, alice_attacker),
            "distinct principals that share a username must never match"
        );
        // An empty SID is a failed lookup, not an identity.
        assert!(!sids_match("", ""));
        assert!(!sids_match(alice_corp, ""));
    }

    #[test]
    fn sid_shape_is_validated_before_it_is_trusted() {
        assert!(looks_like_sid("S-1-5-21-1-2-3-1001"));
        assert!(looks_like_sid("S-1-5-18"));
        // Error text / localized output must not be mistaken for an identity.
        assert!(!looks_like_sid(""));
        assert!(!looks_like_sid("Get-CimInstance : Access denied"));
        assert!(!looks_like_sid("S-1-5-21-abc"));
        assert!(!looks_like_sid("X-1-5-18"));
        assert!(!looks_like_sid("S-1-"));
    }

    #[test]
    fn sid_pair_is_parsed_owner_first() {
        let owner = "S-1-5-21-1-2-3-1001";
        let me = "S-1-5-21-1-2-3-1002";
        let got = parse_sid_pair(&format!("{owner}\r\n{me}\r\n")).unwrap();
        assert_eq!(got, (owner.to_string(), me.to_string()));
        assert!(
            !sids_match(&got.0, &got.1),
            "different users must not match"
        );

        // Blank lines around the output must not shift the pair.
        let got = parse_sid_pair(&format!("\r\n  {owner}  \r\n\r\n  {me}\r\n")).unwrap();
        assert_eq!(got.0, owner);

        // A failed lookup yields nothing usable -> Unknown, never an identity.
        assert!(parse_sid_pair("").is_none());
        assert!(parse_sid_pair(&format!("{owner}\r\n")).is_none());
        assert!(
            parse_sid_pair("Invoke-CimMethod : The system cannot find\r\nthe PID\r\n").is_none()
        );
    }

    #[test]
    fn netstat_row_matching_ignores_the_localized_state_column() {
        let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        // Real `netstat -ano` shape. The state word is localized (here German),
        // which must not matter: only protocol, endpoints and PID are read.
        let text = "\
Aktive Verbindungen

  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    127.0.0.1:54321        127.0.0.1:3000         HERGESTELLT      4242
  TCP    127.0.0.1:9999         127.0.0.1:3000         HERGESTELLT      777
";
        assert_eq!(parse_netstat_owning_pid(text, peer, local), Some(4242));

        // The reverse row (the server's own end) must not match the client's.
        let text_server_side =
            "  TCP    127.0.0.1:3000         127.0.0.1:54321        ESTABLISHED     1\n";
        assert_eq!(
            parse_netstat_owning_pid(text_server_side, peer, local),
            None
        );

        // No matching row -> None -> Unknown, never a wrong PID.
        assert_eq!(parse_netstat_owning_pid("", peer, local), None);
        assert_eq!(
            parse_netstat_owning_pid("  UDP    127.0.0.1:54321  *:*  1234\n", peer, local),
            None
        );
    }

    #[test]
    fn netstat_disambiguates_a_reused_ephemeral_port() {
        // Two connections share the client port to different servers; matching
        // both endpoints is what picks the right owning process.
        let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let text = "\
  TCP    127.0.0.1:54321        127.0.0.1:8080         ESTABLISHED     111
  TCP    127.0.0.1:54321        127.0.0.1:3000         ESTABLISHED     222
";
        assert_eq!(parse_netstat_owning_pid(text, peer, local), Some(222));
    }

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
