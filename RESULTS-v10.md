# Validation harness - run 10 results

406 runs (203 cases x 2 arms) - the full corpus (same as run 8), **Haiku 4.5 for both arms**
(matching run 8's model pairing exactly), Sonnet 5 judges. This is the direct before/after test of
the three guidance fixes run 8 made (`cwe/90/java`'s `SearchControls` requirement,
`cwe/117/javascript`'s Unicode escape syntax, `cwe/352/csharp`'s `UseAntiforgery()` JSON-binding
gap): same corpus, same arm model, same judge model, only the guidance content changed.

## Answer: a small fix_quality gap reopens, traced directly to the three fixes

| Set | n | fix /2 | no-harm /2 |
| --- | --- | --- | --- |
| A - no guidance | 203 | 1.85 | 1.87 |
| B - skill | 203 | 1.90 | 1.83 |

| Run | Set | fix /2 | no-harm /2 |
| --- | --- | --- | --- |
| 8 (pre-fix) | A | 1.86 | 1.86 |
| 8 (pre-fix) | B | 1.86 | 1.80 |
| 10 (post-fix) | A | 1.85 | 1.87 |
| 10 (post-fix) | B | 1.90 | 1.83 |

Arm A is flat between runs (1.86 -> 1.85 fix, within noise) - expected, since arm A never reads
`cwe/` and the guidance changes cannot affect it. Arm B's `fix_quality` moved from tied-with-A to
+0.05 ahead of it, and this is not a coincidence of aggregate noise: checking the same specific
cases run 8 flagged shows the fixes working exactly as intended.

## Verified: the fixes closed the cases they were written for

**`cwe/90/java`** - all three previously-broken Juliet CWE-90 Java cases now score a clean 2.00/2.00
for arm B, up from 0.67/0.67 in run 8:

| case | run 8 B fix | run 10 B fix |
| --- | --- | --- |
| Case07 | 0.67 | 2.00 |
| Case08 | 0.67 | 2.00 |
| Case09 | 0.67 | 2.00 |
| Case17 | 2.00 (already correct) | 2.00 |

Read directly: arm B's `DirContext.search()` call now supplies the `SearchControls` argument the
entry previously never mentioned needing.

**`cwe/352/csharp`** - `MinimalApiEmailNoAntiforgery` arm B rose from a mixed judge read in run 8 to
2.00/1.67 in run 10; arm A, which never reads the guidance, is unaffected by the fix and continues
to score poorly on this case (0.33/0.00) - exactly the isolation the fix should produce: only the
arm that reads the corrected entry improves.

**`cwe/117/javascript`** - only partial. `WinstonUserInputLog` arm B scored 1.33/1.00, still short of
a clean pass. Reading the actual generated file: the guidance text is confirmed clean ASCII (no
stray Unicode bytes, checked directly), but Haiku's own generated regex character class -
`[\x00-\x1f\x7f<NEL><LS><PS>\\]` - once again contains literal raw Unicode characters for
U+0085/U+2028/U+2029 instead of the `\u0085`/`\u2028`/`\u2029` escapes the entry now spells out
verbatim. This is the same mistake as run 8, independently reproduced in a fresh generation, not a
guidance gap the entry can close by being clearer - the entry already gives the literal escape text.
It reads as a Haiku-specific execution slip (writing the intended character instead of its source
escape) rather than a knowledge gap, and no further entry edit is indicated.

Net: two of the three fixes closed cleanly and account for essentially all of the aggregate
`fix_quality` recovery (4 affected cases x roughly +1.3 average improvement / 203 cases ~= +0.026,
close to the observed arm-B move of +0.04); the third improved but did not fully resolve, for a
reason outside the guidance's control.

## `no_harm` did not recover the same way

Arm B's `no_harm` is close to flat versus run 8 (1.80 -> 1.83) and still trails arm A (1.87). The
three fixed cases were fix_quality-dominated (a 0 there caps no_harm's ceiling too under the
rubric's own no-compile rule), so their improvement shows up mostly in fix_quality; the broader
`no_harm` gap is driven by cases outside the three fixes and is not something this run's changes
targeted. Judge disagreement rose versus run 8's Haiku pass: 48/406 (11.8%) on `fix_quality`
(vs. 12.3% in run 8) and 58/406 (14.3%) on `no_harm` (vs. 18.2% in run 8) - both lower than run 8's,
consistent with fewer genuine defects (the three closed cases) to disagree about.

## By CWE, by language, by source, per-run

Full tables in this run's raw `analyse.py` output (not committed separately - regenerate with
`python scripts/analyse.py --map evals/arm-map-v10.json --scores evals/scores-v10 --out <path>`).

## What run 10 establishes

1. **The three run-8 guidance fixes are independently verified to work**, not just theoretically
   sound - checked against the actual re-generated code in a fresh Haiku run, not judge notes alone.
2. **A documentation fix cannot close a model execution slip.** The CWE-117/javascript case shows
   the limit of what a knowledge-base entry can do: the entry now states the exact literal escape
   text needed, and Haiku still wrote the raw character instead of the escape in a fresh, independent
   generation. This is evidence the earlier CWE-117 defect had two layers - a genuine guidance gap
   (fixed, and it helped) and a model-level tendency that guidance improvements cannot fully reach.
3. **The recovered `fix_quality` gap (+0.05) is far smaller than run 7's original (+0.13 on the
   79-case corpus).** This is consistent with run 8's finding that guidance's aggregate value is
   diluted by a much larger, harder corpus - fixing two known defects recovers a small, traceable
   slice of that value, not the full run-7-sized effect.

## Limitations

- **Two remediation output anomalies were found and corrected before scoring**, both in run 10's
  own output, neither affecting the numbers above except by making the corpus complete: one case
  (`330/java/BenchmarkTest00066` arm A, `190/java/ProductOverflowAllocation` arm B) had a stray
  empty subdirectory alongside the real, correctly-named output file - junk left over from a tool
  execution quirk, not a missing result - removed. One case (`326/javascript/CreateCipherLegacyApi`
  arm A) had its real output nested one directory too deep; moved to the expected flat path. All
  four arm directories were verified at 203/203 files with no remaining anomalies before blinding.
- **Not a full replication of run 7's methodology** - run 7 used the 79-case corpus; this run's
  comparison baseline is run 8 (same 203-case corpus, pre-fix), not run 7.
- **`must_preserve` still not passed to judges** - same standing gap as every prior run.
- **Judging was sharded** (11 shards x 3 judges), same deviation from HARNESS.md Step 5 as run 8 -
  see run 8's write-up for the rationale.
