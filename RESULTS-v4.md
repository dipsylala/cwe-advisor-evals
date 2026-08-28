# Validation harness - run 4 results

20 runs (10 cases x 2 arms) on the ten `authored-from-docs-pitfall` cases, scored blind by three
judges who each scored all 20. Scores are the mean across the three. Executed from
[HARNESS.md](HARNESS.md), which was written before the run.

The question: those ten cases were built so the obvious fix is incomplete. Are the traps traps?

## Answer: mostly no

| Set | n | fix /2 | no-harm /2 |
|---|---|---|---|
| A - no guidance | 10 | 2.00 | 1.63 |
| B - skill | 10 | 1.90 | 1.83 |

Nineteen of twenty runs closed the real vector. All three judges reported, independently and in
almost the same words, that the write-ups saw through the decoy in every case: the `os.urandom`
reseed, `math/rand/v2` being newer, the per-operand bounds check, the Express error middleware that
was already present, `ValidateIssuerSigningKey`, the `escapeshellarg`-ed primary branch, the
magic-byte check, and the storage directory already being outside `wwwroot`.

So the batch did not do the job it was built for. Neither arm needed help to tell a decoy control
from the real one, which is the same lesson runs 1-3 taught about tracing: the model is better at
this than the corpus assumed.

## The one exception is arm B, and the guidance caused it

| | fix /2 | no-harm /2 |
|---|---|---|
| CWE-117 / A | 2.00 | 2.00 |
| CWE-117 / B | 1.00 | 1.33 |

`LogForgeOnFailure` is the only case where a trap worked, and it caught the **guided** arm while the
control walked it.

Arm A neutralised the control characters at the call site, correctly said in as many words that
SLF4J placeholders are not the fix, kept the `Throwable` in throwable position, and also fixed the
success-path log statement the scanner had not reported.

Arm B changed the concatenation to a `{}` placeholder - which is exactly the documented trap, and
which its own write-up admits neutralises nothing - and deferred closure to a `logback.xml`
`LogstashEncoder` under an assumed Logback binding, plus a `logstash-logback-encoder` dependency
whose version it left as an unresolved placeholder. Two judges also docked `no_harm` because that
switch reformats every log line the application emits.

All three judges scored `fix_quality` 1 here, and `fix_quality` had **zero** disagreement across
the whole pool, so this deduction is as solid as the run can make it.

### Why the entry produces this

`cwe/117/java/INDEX.md` states the trap correctly in its guidance paragraph - *"Parameterized
logging alone is insufficient without structured output formats"* - but its `Remediation Steps`
open with "Add logstash-logback-encoder", "Configure Logback/Log4j2 to use JSON encoder", "Replace
string concatenation with `{}`". Call-site control-character encoding, which is what arm A did and
what closes the finding in the file the scanner named, appears fifth and is framed as the fallback
"for legacy systems without JSON support".

That is the CWE-78 shape again, and it is now the third instance across four runs: **when an
entry's leading remediation is an infrastructure or configuration change, the guided arm makes that
change and the finding stays open in the code.** CWE-78 said "eliminate the call"; CWE-117 says
"reconfigure the logging backend". Both are defensible architectural advice and both are the wrong
first instruction for a tool remediating one reported line.

## no_harm moved, but not enough to claim

Arm B leads 1.83 to 1.63. **Judges disagreed on `no_harm` in 9 of 20 runs** - that is this run's own
noise estimate, and a 0.20 gap does not clear a 45% disagreement rate. Treat the `no_harm` column as
unresolved.

The disagreement is not random: it is whether disclosed scope creep should cost a point. Six runs
across both arms added allocation or upload size caps the original did not have, one added a
filename allowlist that rejects legitimate names containing spaces or non-ASCII, one changed an API
key's character set from `[a-z0-9]` to base64url. Every one was declared by its author rather than
slipped in. One judge treated declaration as mitigation, two did not. That is a rubric ambiguity,
not a model behaviour, and it should be settled before `no_harm` is used to compare arms again.

## What run 4 establishes

1. **The ten cases do not discriminate on fix quality.** 19 of 20 at ceiling. They are a
   regression guard, not a measuring instrument, and extending the batch in the same style would
   add cost without adding resolution.
2. **One entry defect, confirmed unanimously.** `cwe/117/java` leads with a config change and the
   guided arm consequently ships a code edit that neutralises nothing.
3. **The pattern generalises beyond CWE-78.** Two entries, four runs, same root cause: leading with
   the architectural fix rather than the one at the sink.
4. **`no_harm` needs a rubric decision** on declared behaviour changes before it can carry a
   comparison.

## Limitations

- **n = 10 per arm, one case per CWE.** Every per-CWE cell is a single run. The CWE-117 result is
  one run per arm; it is credible because three judges agreed unanimously and because it matches a
  defect class seen twice before, not because the sample supports it.
- **Cases are authored here.** Their labels are an authoring claim rather than external ground
  truth, unlike the Benchmark and Juliet cases.
- **Nothing was compiled or executed.** `must_preserve` was checked by reading.
- **`must_preserve` was not given to the judges.** It exists in `case.json`, which judges are
  barred from reading, so they applied their own reading of the original's contract - which is
  where the 9/20 disagreement comes from. Passing the stated contract into the judge prompt without
  revealing the trap is the obvious next iteration.
