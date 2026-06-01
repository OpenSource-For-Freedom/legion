# Legion dynamic rule feed

This directory is the GitHub-hosted YARA rule feed for Legion. The Legion YARA
engine fetches rules from here at runtime, caches them under
`<data_dir>/rules/<os>/`, and falls back to the rules compiled into the binary
when offline.

## Layout

Rules are organized per OS. The engine fetches, for each `rule_file` listed in
[`yara_config.json`](../crates/legion-core/yara_config.json), the URL:

```
<rules_repo>/<os>/<rule_file>
```

```
rules-feed/
  linux/    common.yar  linux.yar
  macos/    common.yar  macos.yar
  windows/  common.yar  windows.yar
```

The default `rules_repo` points at this folder on `main`:

```
https://raw.githubusercontent.com/OpenSource-For-Freedom/legion/main/rules-feed
```

To host the feed in a dedicated repository instead, copy this `rules-feed`
layout into that repo and change the `rules_repo` value in `yara_config.json`
(or in the copy written to `<data_dir>/yara_config.json`). No code changes are
required.

## Authoring rules

Rules must stay within the engine subset implemented in
[`legion-core/src/yara.rs`](../crates/legion-core/src/yara.rs):

- **Strings** — text strings with `nocase` / `wide` / `ascii` / `fullword`
  modifiers, and hex strings with nibble wildcards (`4?`, `?A`, `??`) and jumps
  (`[n]`, `[n-m]`, `[n-]`).
- **Conditions** — `true` / `false`, `$a`, `#a <op> N`, `filesize <op> N[KB|MB|GB]`,
  `N of them`, `any` / `all of (set)`, grouped with `( )` and combined with
  `not` / `and` / `or`.
- **Meta** — `severity` (`Critical` / `High` / `Medium` / `Low` / `Info`) and
  `description` are surfaced in alerts.

Regex string bodies and module references (`pe.`, `math.`, `for` loops) are not
supported; rules that use them are skipped at load time with a warning rather
than breaking the whole feed.

Run `legion yara update` to pull the latest rules for the current OS, then
`legion yara rules` to confirm they loaded without warnings.
