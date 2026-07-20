# DPRK workstation indicators

**Status: Real.** `crates/legion-core/src/dprk.rs`

Detects the Contagious Interview cluster (MITRE **G1052** — also
DeceptiveDevelopment, Famous Chollima, DEV#POPPER) on a developer's own machine.

Generation 3 of this campaign (PolinRider / TasksJacker, 2026) is why this
exists: it drops the "the developer was socially engineered" precondition by
injecting into *existing, trusted* repositories via account takeover. Opening a
repo you already trust is enough.

## Rules

| Rule | Detects | ATT&CK |
|---|---|---|
| **DPRK-1** | Staging paths (`~/.n2/pay`, `~/.n2/bow`, `~/.n2/mlip`, `~/.npl`) and interpreters running out of them | T1059.006/.007 |
| **DPRK-2** | Connection to a BeaverTail C2 port (1224, 1418, 1476, 1478) on a **public raw IPv4 literal** | T1571 |
| **DPRK-3** | Private Use Area codepoints in `.js`/`.ts` source | T1027 |
| **DPRK-4** | Obfuscated payload appended after a config file's default export | T1027 |
| **DPRK-5** | `.vscode/tasks.json` with `runOn: folderOpen` **and** a fetch/eval command | T1059 |

Every finding names a concrete artifact. Findings reconcile, so a cleaned-up
artifact stops alerting.

## Deliberately NOT detected

Each of these is a false-positive trap, and the reasons are in the module docs:

- **`postinstall` spawning `curl`/`wget`.** The obvious rule and the worst one:
  `sharp`, `puppeteer`, `playwright`, `node-gyp`, `canvas`, `better-sqlite3`,
  `electron` and `node-sass` all download binaries at install time by design. It
  fires on a clean `npm ci` in most repos. The signal is the *destination*.
- **"Obfuscated JavaScript", long base64, `eval` presence.** Every minified
  bundle in `node_modules` looks exactly like this.
- **Bare zero-width joiners.** Legitimate emoji contain ZWJ and U+FE0F. Only
  Private Use Area codepoints are flagged.
- **Telegram or AnyDesk presence.** Both legitimate; corroboration only.
- **Blockchain RPC egress.** Excellent signal on a workstation doing no web3
  work, worthless in a crypto shop. Belongs behind a toggle, not default-on.

## Verify

```bash
cargo test -p legion-core --lib dprk
```

Planting a TasksJacker `tasks.json`, a padded config payload and hidden PUA
codepoints fires 3 findings, while an emoji-laden source file and a legitimate
config with helpers after the export stay silent.

## Limits

- **PUA codepoints are not unique to attackers.** The original claim that "no
  legitimate JavaScript carries PUA codepoints" was wrong: charset conversion
  tables contain them because mapping them is the whole job. The sweep therefore
  skips dependency caches (`.bun/install/cache`, `.cargo/registry`,
  `.npm/_cacache`, `.pnpm-store`, `.gradle/caches`, `.m2/repository`) and scans
  the developer's own source, which is what these campaigns inject into. A
  vendored charset table committed into a project would still be flagged.
- DPRK-1's paths are exact strings and are **one actor commit from useless**.
  Kept because the check costs a handful of `stat` calls.
- DPRK-2 only inspects IPv4 literals; a hostname on those ports is ignored.
- The tree sweep is capped at 20,000 files and skips files over 2 MB.

## One correction worth recording

The persona is **PolinRider**, not "paulinrider", and it is a git commit-metadata
email (`PolinRider@outlook.com`), **not an npm account** — `maintainer:polinrider`
returns zero packages from the npm registry. Shipping it as an IoC would match
nothing, forever.
