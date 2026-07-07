# Live PoH Adaptive Quorum — Batch 309

Live Proof-of-Humanity uses one deterministic quorum rule from genesis bootstrap through mature network scale.

## Production posture

- A Live PoH panel may contain **1 to 10 jurors**.
- The first up-to-3 jurors are **active reviewers**.
- Any remaining jurors are **watching observers**.
- The maximum mature panel is **10 jurors: 3 active reviewers and 7 watching observers**.
- The pass/fail decision is an integer **n-of-m percentile threshold over active reviewers only**.
- Watching observers are audit witnesses. They may accept/attend, but they do not block finalization.

## Default threshold

The default threshold is frozen as the rational integer threshold `2/3`:

| Active reviewers | Required pass verdicts |
| --- | --- |
| 1 | 1 |
| 2 | 2 |
| 3 | 2 |

The threshold is represented by integer numerator/denominator fields instead of floating point values so all nodes compute identical results.

## Bootstrap behavior

This model allows the same code path to operate with:

- one genesis Live account acting as the first active reviewer;
- two active reviewers during early expansion;
- three active reviewers once enough Live jurors exist;
- up to seven additional watchers as the community matures.

No protocol logic change is required as the network grows.

## Consensus safety

The selected panel and frozen quorum summary are stored in the Live PoH case state at `POH_LIVE_JUROR_ASSIGN` time. Finalization recomputes the active reviewer set and required pass threshold deterministically from the frozen case data.
