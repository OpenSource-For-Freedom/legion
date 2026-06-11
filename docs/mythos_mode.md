# PONCHO Mythos Mode

Mythos mode is Legion's local, read-only analyst profile for rootkit, kernel-view, and alert-listener hunting.

Public grounding used for the rules:

- MITRE ATT&CK T1014 Rootkit: rootkits hide programs, files, network connections, services, drivers, and other OS artifacts by intercepting or modifying system information paths across Linux, Windows, and macOS.
- MITRE ATT&CK T1547.006 Kernel Modules and Extensions: adversaries can use Linux loadable kernel modules and macOS kernel extensions for persistence and privilege escalation, including rootkit behavior in ring 0.
- MITRE ATT&CK T1562.001 Impair Defenses: tampering with audit, journal, EDR, or alert-listener telemetry can suppress evidence and blind local detection.

Implemented coverage:

- OS detection is the first Mythos decision point. PONCHO maps the host to a hunt lane before applying generic rules: `windows-kernel`, `linux-kernel`, `macos-kernel`, `package-supply-chain`, `container-runtime`, or `firmware-boot`. The Agent UI shows the detected OS, architecture, kernel/version, and selected lane at the top of the PONCHO tab.
- `SYS-09` detects rootkit and stealth indicators such as syscall hooks, hidden process/file language, known Linux rootkit families, and `ld.so.preload` behavior.
- `SYS-10` detects kernel module or macOS kext load/unload activity such as `modprobe`, `insmod`, `rmmod`, `kextload`, `kextunload`, `.ko`, and kernel module language.
- `SYS-11` detects audit/journal/EDR/listener tamper signals such as audit log clearing, journal corruption, sensor stops, and security tool disablement.
- `SI-3-MYTHOS-NPM-PIP-WORM` and `DEV-09` detect npm/pip package intelligence tied to worm-style traversal, lifecycle execution, typosquat/impersonation, credential theft, and dependency propagation.
- `SI-4-MYTHOS-PKG-LIFECYCLE`, `SI-4-MYTHOS-PATH-TRAVERSAL`, `AC-6-MYTHOS-CREDENTIAL-SCRAPE`, `DEV-10`, and `DEV-11` detect local heuristic anomalies around install scripts, out-of-tree writes, archive/path traversal, package-manager execution, and secret access.
- `MythosNeuralHunter` is a local deterministic neural-style weighted scorer. It does not call external services or mutate the host; it scores active alerts, local events, YARA hits, and Mythos rules into a hunt posture.

Local model assignment:

```powershell
ollama create legion-mythos:qwen3-8b -f agents\poncho\models\Modelfile.mythos
```

The assigned Mythos model is `legion-mythos:qwen3-8b`, built from `qwen3:8b`. The fallback remains `qwen3:8b` / `qwen3:4b` depending on local availability and configuration.