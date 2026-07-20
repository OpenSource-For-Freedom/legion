# Security model

**Status: Partial — Linux solid, Windows recently corrected.**

## Layers

1. **Loopback only.** The dashboard and API bind `127.0.0.1`. Never expose it;
   there is no multi-user authorisation model.
2. **Session token.** A per-process 64-hex token gates every `/api/*` route,
   delivered as a `SameSite=Strict` cookie and accepted as
   `Authorization: Bearer` or `X-Legion-Token` for same-user CLI clients.
3. **Peer credentials.** A loopback socket is reachable by *every* local user, so
   the peer's identity is checked — `/proc/net/tcp` UID on Linux, SID comparison
   on Windows. A different local user is refused.
4. **Elevation.** OS-native only: polkit/`pkexec` or `sudo` on Linux, UAC on
   Windows. Never silent, never hangs a non-interactive session. `--no-elevate`
   opts out and costs only privileged telemetry.
5. **Feed integrity.** Bodies are size-capped and streamed; model and runtime
   downloads are SHA-256 verified before use; KEV supports a pinned hash.

## Verify

```bash
cargo test -p legion-web peercred
cargo test -p legion-core --lib privilege
```

## Limits

- **An undeterminable peer fails open.** The session token still gates
  `/api/*`, and failing closed would lock an operator out of their own dashboard
  on any lookup hiccup — but it is a deliberate tradeoff, not an oversight.
- IPv6 peers return `Unknown` and therefore fail open.
- `is_elevated()` shells out (`id -u` / `net session`) on every call rather than
  reading the token directly.
- macOS has no peer-credential implementation at all.

## Fixed here, worth knowing

Two on the Windows path, both of which shipped because **it had no tests** — the
module claimed it was "compiled + exercised only on Windows CI", and CI only
ever compiled it:

1. It compared bare user **names**, taking the last segment of `DOMAIN\user`, so
   `CORP\alice` and `ATTACKER\alice` were the same principal and the attacker
   got a session cookie for a root-level API. Now SID comparison.
2. The owner came from `tasklist /v` CSV **column 6** — a hardcoded index into
   localized output, which silently yields the wrong field on a non-English host.

Every parser is now a pure function over captured output, tested on all
platforms.
