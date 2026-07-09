# git_paca feedback intake (real-world SFT examples)

This folder receives training examples produced by the **git_paca** malicious-
package detonation pipeline. Each line of `feedback.jsonl` is one SFT record in
the ares_train `to_messages()` schema:

    {"messages": [
       {"role": "system",    "content": "<SYNTHESIS_SYSTEM>"},
       {"role": "user",      "content": "<instruction>\n\n<evidence: the finding>"},
       {"role": "assistant", "content": "<operator-approved analyst note>"}
     ],
     "meta": {"scenario": "git_paca_detonation", "backend": "real",
              "source": "git_paca", "run_key": "...", "human_verdict": "..."}}

## Where it comes from

git_paca detonates a package, legion-ares synthesizes an analyst note, and the
operator confirms or corrects it in the detonation console. Confirmed/corrected
notes are curated here by `feedback/curate.py` in the git_paca repo. Because the
evidence is a REAL detonation and the answer is human-approved, these are higher-
signal than the synthetic teacher-generated scenarios.

## How to use it

Fold `feedback.jsonl` into the next training build alongside the synthetic set
(it is already in `to_messages()` form). It is a plain append-only JSONL; dedupe
on `meta.run_key` if you re-curate.

## Writer

Written by the git_paca repo:
`F:\dev\git_paca\PR-1-Behavioral-Sandbox\feedback\curate.py`
Override the location with `GIT_PACA_TRAINING_INTAKE` or `LEGION_ARES_DIR`.
