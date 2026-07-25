# Posture score

**Status: Real.** `dashboard.html` — `computeScore`, `scoreBreakdown`

A single 0-100 number with a letter grade, computed client-side and labelled
"local heuristic" in the UI.

## Weights

| Input | Each | Cap |
|---|---|---|
| Critical alert | −20 | 50 |
| High alert | −7 | 25 |
| Medium alert | −1.5 | 25 |
| Low alert | −0.5 | 5 |
| Blacklisted IP in use | −3 | 15 |
| Feeds never pulled | −10 | — |
| Never scanned | −15 | — |

Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 45, F below.

Caps stop one noisy category pinning the score at zero. **The gauge prints its
own arithmetic** underneath — "−25 72 medium alerts", "−10 threat feeds never
pulled" — so the number can be interrogated rather than argued with.

## Sanity checks

| Scenario | Score | Grade |
|---|---|---|
| Nothing open | 100 | A |
| 72 medium alerts | 75 | C |
| 1 critical | 80 | B |
| 2 crit + 2 high + 4 med | 39 | F |

## Limits

- Computed in the browser, not the backend, so it is a presentation-layer
  heuristic and not an API field.
- Counts only unacknowledged alerts, since that is what the queue holds.

## Fixed here, worth knowing

The formula deducted for **Critical and High only**. Medium and Low contributed
nothing, so a machine carrying 72 unacknowledged vulnerable packages scored a
perfect **100 / A**. That is not a rounding problem — most of the queue was
absent from the formula that claims to summarise it, and a score which ignores
its own queue teaches operators to ignore the score. Never-scanned also moved
from −5 to −15: a host nobody has looked at should not be a near-A.
