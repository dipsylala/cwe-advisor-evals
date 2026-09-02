# Validation harness - run 9 results

406 runs (203 cases x 2 arms) - the full corpus (same as run 8), **Sonnet 5 for both arms**, Sonnet
5 judges. This is the first Sonnet-5 pass over the full 203-case corpus (run 5 used Sonnet 5 on the
earlier 79-case corpus) and the first Sonnet-5 pass since the three guidance fixes from run 8
(`cwe/90/java`, `cwe/117/javascript`, `cwe/352/csharp`) landed.

## Answer: fix_quality saturates again, no_harm gives guidance a small edge

| Set | n | fix /2 | no-harm /2 |
| --- | --- | --- | --- |
| A - no guidance | 203 | 1.98 | 1.88 |
| B - skill | 203 | 1.98 | 1.91 |

This replicates run 5's Sonnet-5 headline (`fix_quality` saturated, guidance's measurable effect
shows up only in `no_harm`) on a corpus more than twice the size and including all the deliberate
wrong-fix trap cases run 5 never saw. Judge disagreement: 12/406 (3.0%) on `fix_quality` - the low
number itself is evidence of saturation, there is little left to disagree about - and 50/406
(12.3%) on `no_harm`.

## By CWE, By language, By case source, Per-run

Full tables in this run's raw `analyse.py` output (not committed separately - regenerate with
`python scripts/analyse.py --map evals/arm-map-v9.json --scores evals/scores-v9 --out <path>`).
Nothing in the by-CWE breakdown stands out beyond normal small-n noise: every CWE with n >= 8 sits
at or above 1.9 on both criteria for both arms.

## What run 9 establishes

1. **Sonnet 5's saturation is not an artifact of the smaller 79-case corpus.** Run 5 raised the
   possibility that the easier, more homogeneous 79-case set was why Sonnet 5 showed no
   `fix_quality` gap. Run 9 shows the same saturation on the full, harder 203-case corpus -
   including the `authored-top15-fix-complexity` and `authored-from-docs-pitfall` cases built
   specifically to have a plausible wrong fix. At this model's capability level, guidance still has
   nothing to add to whether the vulnerability gets found and closed.
2. **`no_harm` remains the one place guidance measurably helps Sonnet 5** (1.88 -> 1.91), consistent
   with runs 5 and 6's finding on the smaller corpus.
3. Low `fix_quality` disagreement (3.0%) confirms the ceiling reading rather than masking it - judges
   are not disagreeing about hard cases, they are agreeing the vast majority are simply correct.

## Limitations

- **Not a controlled before/after** on the guidance fixes specifically - Sonnet 5 was already at
  ceiling on `fix_quality` before those fixes existed (run 5), so this run cannot show whether they
  helped Sonnet; it can only show they did not hurt it. Run 10 (Haiku 4.5, same corpus) is the
  before/after comparison that matters for those fixes - see [RESULTS-v10.md](RESULTS-v10.md).
- **Two arm-B outputs needed a manual retry** during this run: one agent (CWE-22/python,
  `ReportDownloadSymlinkEscape`) replied with the full write-up text instead of writing the file and
  replying with its path - a soft failure the Workflow resume mechanism does not catch, since the
  agent call itself did not error. Caught by a post-run file-count check (203 expected per arm,
  202 found), and re-run individually. Two stray nested directories were also found and removed
  from run 10's output during the same audit (see run 10's limitations) - neither affected run 9.
- **`must_preserve` still not passed to judges** - same standing gap as every prior run.
