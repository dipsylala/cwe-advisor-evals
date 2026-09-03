# Validation harness - run 11 results

744 runs (372 cases x 2 arms) - the full corpus, grown from run 10's 203 cases via the ongoing
per-language-coverage and top-15-depth campaigns (`TODO.md`). **Haiku 4.5 for both arms** (same
pairing as runs 7, 8 and 10), Sonnet 5 judges, 3 judges per run. This is the first run at the
larger corpus size on Haiku; run 9 previously confirmed Sonnet 5 saturates at this scale.

## Answer: the fix_quality gap holds at nearly double the corpus, no_harm stays flat

| Set | n | fix /2 | no-harm /2 |
| --- | --- | --- | --- |
| A - no guidance | 372 | 1.82 | 1.81 |
| B - skill | 372 | 1.89 | 1.79 |

| Run | Corpus | Set | fix /2 | no-harm /2 |
| --- | --- | --- | --- | --- |
| 7 | 79 | A / B | 1.84 / 1.97 | - |
| 8 | 203 | A / B | 1.86 / 1.86 | 1.86 / 1.80 |
| 10 | 203 (post-fix) | A / B | 1.85 / 1.90 | 1.87 / 1.83 |
| 11 | 372 | A / B | 1.82 / 1.89 | 1.81 / 1.79 |

The +0.07 `fix_quality` gap sits between run 10's +0.05 (same 203-case corpus, guidance fixes
applied) and run 7's original +0.13 (smaller 79-case corpus) - consistent with run 8's finding that
a larger, harder corpus dilutes guidance's aggregate edge without erasing it. `no_harm` again shows
no guided advantage on Haiku (-0.02), matching runs 8 and 10's pattern and contrasting with Sonnet
5's small but consistent guided `no_harm` edge on the same corpus shape (runs 5, 9).

Judge disagreement: `fix_quality` 74/744 (9.9%), `no_harm` 125/744 (16.8%) - both below the +0.07
gap being measured for `fix_quality`, in line with the noise-vs-signal threshold prior runs have
used.

## Notable: CWE-94 is guidance's clearest win this run

CWE-94 (Code Injection) shows the largest gap of any CWE: fix_quality 1.29 (A) vs 1.85 (B), n=22.
Arm A scores near zero on cases needing an embedded scripting/formula engine sandboxed or replaced
rather than patched - `GroovyShellEvaluate` (0.00), `ScriptEngineJavaScriptEval` (0.00),
`IronPythonScriptEngineExecute` (0.00), `JexlEngineUnsandboxedEval` (0.33),
`VmRunInNewContextEval` (0.33), `AssemblyLoadUserBytes` (0.33) - the un-guided arm's typical failure
here is patching around the eval call (input filtering, denylisting) rather than removing or
properly confining the dynamic-execution surface, which is exactly the class of fix `cwe/94`'s
guidance is written to redirect. CWE-90 (LDAP injection, n=10) shows a similar shape: 1.70/1.37 (A)
vs 2.00/2.00 (B).

## Notable: a reproducible CWE-502 pattern - guided fixes swap wire format without full disclosure

Across three languages, arm B's CWE-502 fixes repeatedly replace the vulnerable deserializer with a
different wire format (gob/PHP-serialize -> JSON) as part of closing the gadget-chain vector, and
several write-ups do not flag this as a breaking compatibility change for existing producers or
callers - the pattern the harness's own `no_harm` rubric is built to catch. All three judges
independently made the identical, specific observation on each case, unprompted:

- **`OrderEventQueueDeserialize` (java)** - fix_quality 1.00, no_harm 0.00 (all 3 judges). All three
  independently state the fix calls `ObjectInputFilter.Config.setSerialFilter()` inside a per-message
  `onMessage()` handler; that setter is process-wide and documented as callable at most once per JVM
  (`IllegalStateException` on a second call), so the fix breaks every message after the first.
  **Reproduced** on JDK 26: a second `Config.setSerialFilter()` call throws
  `IllegalStateException: Serial filter can only be set once`. `cwe/502/java` never mentions the
  per-stream `ois.setObjectInputFilter()` / process-wide `Config.setSerialFilter()` distinction -
  a guidance gap, not a model slip.
- **`CartCookieDecodeUnserialize`, `CartLegacySerializedMigration` (php)** - no_harm 1.00 (both,
  unanimous across judges). The fix swaps `unserialize()` for `json_decode()`, which closes the
  gadget-chain vector but silently breaks decoding of any cookie written by an existing
  PHP-`serialize()` producer; `unserialize($payload, ['allowed_classes' => false])` would close the
  same vector while staying wire-compatible.
- **`JobQueueGobPrivilegeField`, `GobDecodeUntrustedPayload` (go)** - no_harm 1.00-1.33. Same shape:
  the DTO/mass-assignment fix is judged correct, but the accompanying gob-to-JSON format swap breaks
  existing gob producers, and only one of three judges considered it adequately disclosed in the
  write-up rather than just the signature change.

This is a repeatable, cross-language finding, not a single case's noise - worth a follow-up read of
`cwe/502`'s php/go/java entries to check whether they're steering toward a format swap where a
narrower, format-preserving fix (allowlist deserialization, restricted gob types) would serve.

## By CWE, by language, by source, per-run

Full tables in this run's raw `analyse.py` output (not committed separately - regenerate with
`python scripts/analyse.py --map evals/arm-map-v11.json --scores evals/scores-v11 --out <path>`).

## What run 11 establishes

1. **The Haiku `fix_quality` gap is stable across a near-doubling of corpus size** (203 -> 372
   cases), landing between runs 7 and 10's prior measurements rather than collapsing the way run 8
   showed it could when the corpus grew without a matching guidance pass.
2. **CWE-94 and CWE-90 are where the guidance earns its keep on Haiku** - both show large,
   broad-based gaps (not single-case artifacts) concentrated in cases needing an architectural fix
   (remove/sandbox a dynamic-execution engine) rather than a local patch.
3. **A new, specific, cross-language `no_harm` defect candidate**: CWE-502 guided fixes trending
   toward an undisclosed wire-format change. Flagged for follow-up, not fixed in this run.

## Limitations

- **Tooling anomalies found and corrected before scoring, same class as run 10's.** ~90 arm outputs
  (both arms) had an extra `{id}/` directory created alongside the correctly-placed `{id}.md` file -
  harmless debris from the arm prompt's own `mkdir -p` step, removed. 21 outputs had their real
  content nested one directory too deep (`{id}/{id}.md`); flattened to the expected path. One case
  (`22/python/ReportDownloadSymlinkEscape`, arm B) produced its full write-up as the agent's final
  reply instead of writing it to disk at all; re-run once as a single follow-up task. All 744
  expected files were confirmed present, and `git status --porcelain evals/cases` was confirmed
  clean, before blinding.
- **Judging was interrupted by a session limit partway through** (13 of 57 judge-segment agents
  completed, one more finished writing to disk moments after being reported failed) and resumed as a
  fresh, targeted retry of the exact 43 missing files once the limit reset. All 57 files were
  re-validated afterward (2,232 of 2,232 expected scores present, correct entry counts, valid JSON)
  before running `analyse.py` - the interruption affected wall-clock time, not data completeness.
- **`must_preserve` still not passed to judges** - same standing gap as every prior run.
- **Judging was sharded** (19 shards of up to 40 runs x 3 judges), same deviation from HARNESS.md
  Step 5 as runs 8 and 10, needed at this pool size for judge context.
- **Two judge claims were reproduced directly, the rest were not.** The `ObjectInputFilter`
  set-once claim (JDK 26) and the `crypto/rand.Text()` single-return compile error
  (`330/go/MathRandSessionId` arm B, 0.00 fix - Go 1.25) were both run and confirmed. Other
  judge-stated mechanisms (multer `file.buffer` absent inside `fileFilter`, `@fastify/csrf-protection`
  needing an explicit hook, `size_t` underflow in `125/cpp/TelemetryClaimedLengthRead`) are plausible
  and unanimous across judges but were not reproduced here - check before editing an entry on them.
- **Not a controlled before/after against any single prior run** - the corpus grew substantially
  since run 10 (new top-15 depth and fix-complexity cases dominate the increase), so run 11's
  aggregate numbers are informative on their own terms but not a clean isolate of any one variable
  the way runs 9/10's paired comparisons were.
