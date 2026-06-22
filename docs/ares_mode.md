# ARES Mode

Ares mode is Legion's local, read-only analyst profile for rootkit, kernel-view, and alert-listener hunting.

Public grounding used for the rules:

- MITRE ATT&CK T1014 Rootkit: rootkits hide programs, files, network connections, services, drivers, and other OS artifacts by intercepting or modifying system information paths across Linux and Windows.
- MITRE ATT&CK T1547.006 Kernel Modules and Extensions: adversaries can use Linux loadable kernel modules for persistence and privilege escalation, including rootkit behavior in ring 0.
- MITRE ATT&CK T1562.001 Impair Defenses: tampering with audit, journal, EDR, or alert-listener telemetry can suppress evidence and blind local detection.

Implemented coverage:

- OS detection is the first Ares decision point. ARES maps the host to a hunt lane before applying generic rules: `windows-kernel`, `linux-kernel`, `package-supply-chain`, `container-runtime`, or `firmware-boot`. The Agent UI shows the detected OS, architecture, kernel/version, and selected lane at the top of the ARES tab.
- `SYS-09` detects rootkit and stealth indicators such as syscall hooks, hidden process/file language, known Linux rootkit families, and `ld.so.preload` behavior.
- `SYS-10` detects kernel module load/unload activity such as `modprobe`, `insmod`, `rmmod`, `.ko`, and kernel module language.
- `SYS-11` detects audit/journal/EDR/listener tamper signals such as audit log clearing, journal corruption, sensor stops, and security tool disablement.
- `SI-3-ARES-NPM-PIP-WORM` and `DEV-09` detect npm/pip package intelligence tied to worm-style traversal, lifecycle execution, typosquat/impersonation, credential theft, and dependency propagation.
- `SI-4-ARES-PKG-LIFECYCLE`, `SI-4-ARES-PATH-TRAVERSAL`, `AC-6-ARES-CREDENTIAL-SCRAPE`, `DEV-10`, and `DEV-11` detect local heuristic anomalies around install scripts, out-of-tree writes, archive/path traversal, package-manager execution, and secret access.
- `AresNeuralHunter` is a local deterministic neural-style weighted scorer. It does not call external services or mutate the host; it scores active alerts, local events, YARA hits, and Ares rules into a hunt posture.

Local model assignment:

The Ares model is **chosen automatically from detected hardware** so it stays
fully GPU-resident. Thresholds are sized by the model's *loaded* footprint
(weights + KV cache + buffers), not its on-disk size, with ~1 GB left for the
desktop: ≥8 GB VRAM → `qwen3-8b` (~6.6 GB loaded), 6–8 GB → `qwen3-4b`
(~5.3 GB loaded), <6 GB incl. 4 GB laptop GPUs → `qwen3-1.7b` (~2 GB loaded),
no GPU → a capped CPU base. A model that doesn't fully fit is split to CPU by
Ollama and becomes minutes-slow, which is why a 4 GB card runs the 1.7B rather
than the 4B. Legion builds the chosen tier on startup, but you can build any
tier by hand from the same embedded Modelfile (edit the `FROM` line for the
base you want):

```powershell
ollama create legion-ares:qwen3-1.7b -f agents\ares\models\Modelfile.ares
```

Operators can override the automatic choice by turning off **automatic model
selection** in the AGENT → CONFIGURE dialog and pinning a specific model.

> **What Ares is (and isn't).** The Ares persona is a local **qwen3-based**
> analyst profile — a smaller, fully-local analog of a cloud-assistant persona,
> not a substitute for one. It is **not** Claude, Anthropic, or any other
> third-party model, and the system prompt instructs it never to claim to be one
> (enforced in `Modelfile.ares` and `crates/legion-ares/src/knowledge.rs`,
> and locked by a unit test). The Qwen3 base models are © Qwen Team, Alibaba
> Cloud under Apache-2.0; see [`NOTICE`](../NOTICE) for attribution.