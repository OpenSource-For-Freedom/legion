---
license: mit
base_model: Qwen/Qwen3-4B
base_model_relation: finetune
library_name: gguf
pipeline_tag: text-generation
language:
  - en
tags:
  - security
  - blue-team
  - threat-hunting
  - cybersecurity
  - incident-response
  - qwen3
  - gguf
  - ollama
  - legion
---

# Legion Ares

Ares is the on-device blue-team analyst built into Legion. It reads the findings that Legion's detection engine has already confirmed (alerts, rule hits, YARA matches, OSV vulnerabilities, and the local posture score) and writes a short, grounded summary for the operator: what the overall picture is, which finding matters most and why, and the single next action to take. Every claim points back to a concrete artifact (a file path, IP, package, or rule id), and it does not invent indicators.

The model runs fully local through Ollama. The Legion app pulls it on first launch from the distribution manifest, checks the download against a SHA-256, and registers it with Ollama. Nothing about your machine leaves your machine.

## What it is

- Base model: Qwen/Qwen3-4B
- Method: QLoRA fine-tune (4-bit NF4 base, LoRA rank 32)
- Format: GGUF, Q4_K_M quant, built for Ollama
- Size: about 2.5 GB on disk
- Language: English

## What it does

Ares takes a block of confirmed findings and turns it into a few sentences an operator can act on. It is not a chatbot and not a generalist. It has one job: grounded synthesis of security findings, in plain text, with no markdown, no restating the list line by line, and no claims of active compromise from rule candidates alone. When there are no findings, it says the host looks clean and names what was checked.

Input (what Legion's engine produces):

```
Local posture: ELEVATED (score 0.50).

CONFIRMED FINDINGS:
ACTIVE ALERTS (critical/high):
  [High] npm postinstall script executed - node_modules/evil-pkg/install.js
RULE HITS:
  [High] dev DEV-04 - postinstall touches process.env
```

Output:

```
The host is at an elevated posture because an npm postinstall script ran from
evil-pkg and reached into process.env, which rule DEV-04 flags as suspicious.
That postinstall execution is the finding that matters most, since it is a
common supply-chain foothold. Isolate the package, read install.js, and review
the dependency before trusting the build again.
```

## How it was trained

The data is grounded synthesis pairs across the scenario types Legion detects: malicious peers, kernel rootkits, npm supply-chain, vulnerable packages, Windows persistence, YARA droppers, and clean baselines. A local teacher model wrote each gold answer, and every pair had to clear the same automated checks the project uses to score the student, so only grounded, plain-text, correctly-cited answers made it into the set. The model also sees several wordings of the same instruction during training, so it behaves the same whether the calling code asks tersely or in detail.

A build only ships if it clears all of these on a frozen test set:

- zero invented indicators
- grounding at or above 0.95
- plain-text format at or above 0.98
- citation coverage at or above 0.80
- low restatement (anti-parrot) at or above 0.90

## Running it

Inside Legion this is automatic. The app reads its distribution manifest, downloads the GGUF, verifies the hash, and runs `ollama create`.

To run it by hand, download the GGUF from this repo and register it with Ollama:

```
ollama create legion-ares -f Modelfile   # Modelfile: FROM ./legion-ares-qwen3-4b.Q4_K_M.gguf
ollama run legion-ares
```

## Limitations

- It only summarizes findings it is handed. It does not detect anything on its own. Legion's deterministic engine does the detection.
- It is tuned for short security syntheses in English. It is not a general assistant.
- By design it will not raise anything that is not in the findings.

## License

MIT, for the Legion Ares fine-tune and the surrounding Legion code. The base model is Qwen3-4B, released by Alibaba under Apache 2.0; those terms still cover the underlying weights, so keep the Qwen attribution if you redistribute.
