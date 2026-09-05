# Validation harness - run 15 results

1116 write-ups judged (372 cases x 3 sets), **Haiku 4.5 guided arm, Sonnet 5 judges**, `must_preserve`
in the header. First run under the frozen-control design (HARNESS.md, **What a run is**): the
unguided arm was not re-run. The three sets in one blind pool:

- **A** - run 13's unguided outputs, with the 14 cases in the four slots re-edited after run 13 taken
  from run 14's post set (the composite the root README reports). Copied verbatim to `runs-v15/A`.
- **B-pre** - the matching guided composite, copied verbatim to `runs-v15/B-pre`.
- **B-post** - 372 fresh guided runs under the byte-identical run-11 prompt, after one change:
  SKILL.md Step 5 gained **Check every name the fix introduces exists** (commit `f19ead2`) - list
  every API, package, class and import the fix adds that the original did not, source each to the
  loaded guidance, the codebase, or the standard library, replace what cannot be sourced, and reread
  the fix as a compiler would, including callers of anything whose signature changed.

The change under test is the self-check. Runs 13 and 14 had traced the guided arm's remaining
losses mostly to names rather than approaches - an npm package that does not exist, a method the
class does not have, a duplicate declaration, a caller not updated - and the self-check was the
cheapest candidate fix: an instruction, not tooling.

## Answer: no effect

| Set | n | fix /2 | no-harm /2 | clean (2.00/2.00, all judges) |
| --- | --- | --- | --- | --- |
| A (frozen) | 372 | 1.75 | 1.72 | 253 |
| B-pre (frozen) | 372 | 1.89 | 1.76 | 262 |
| B-post (fresh, with self-check) | 372 | 1.89 | 1.73 | 259 |

B-post and B-pre are the same population judged by the same panel, differing only by the sample
and the self-check. They are level on fix, -0.03 on no_harm, -3 clean. Per case, 21 moved up by a
point or more on either axis and 28 moved down - the fresh-sample churn runs 12-14 showed on
subsets, now visible on the corpus.

The metric the self-check was written for did not move either. Counting cases where at least one
judge's note names a non-existent, invented, undefined, mistyped or non-compiling identifier:

| Set | cases with a name-slip note | notes |
| --- | --- | --- |
| A | 24 | 41 |
| B-pre | 24 | 38 |
| B-post | 24 | 41 |

The run-13 slips the instruction was modelled on did close - `90/java/Case08` 0.00/0.67 ->
2.00/2.00 (no double declaration this time), `416/cpp/EventBusDanglingObserver` 0.33/0.67 ->
2.00/2.00 (caller updated), `117/csharp/LoginFailureLogConcat` 0.33/1.67 -> 2.00/2.00 (the right
`using`), `94/java/JexlEngineUnsandboxedEval` held at 2.00/2.00 with a real `JexlSandbox` - and an
equal number of the same shape opened elsewhere, each checked against the case files before being
listed here:

- `862/java/MethodSecurityNotEnabledGlobally` 2.00/2.00 -> 0.33/0.00: declares a second
  `SecurityConfig` class in a package that already has one, and calls `getOwner()`/`getManagerId()`
  on an entity that has neither.
- `117/javascript/WinstonUserInputLog` 2.00/2.00 -> 0.67/0.67: three raw U+0085/U+2028/U+2029
  characters inside regex literals, a `SyntaxError` in JavaScript source.
- `787/cpp/NewArrayComputedSizeOverflow` 2.00/1.67 -> 0.33/0.67: returns a `std::vector` from a
  function the shown code still declares as `uint8_t*`; the Behaviour changes section says the
  return type changed, the code does not.
- `209/javascript/RouteBypassesErrorHandler` 2.00/2.00 -> 1.33/0.67: calls `next(error)` in a handler
  declared `(req, res)`.
- `434/csharp/ShortReadMagicByteBypass`, `862/php/OrderIndexAdminBranchSwap`, `89/java/Case03`: a
  `ReadAtLeastAsync` overload that does not exist, `Gate::authorize` on abilities never defined,
  `setString()` on a variable still typed `Statement`.

The write-ups show why. The self-check asks for a sourced list of new names; 20 of 372 B-post
Behaviour-changes sections mention verifying a name, and 20 of 372 B-pre sections do, written before
the instruction existed. One B-post record carries an `assumptions` entry. On Haiku the instruction
was read and not executed, in the same way run 12's Thymeleaf bullet was quoted and not followed:
a SKILL.md sentence is a probability, and for a self-verification step it is a low one.

## What the frozen control shows

A and B-pre were last scored by run 13's and 14's panels. Re-judged here:

| Set | previous panel | this panel | drift |
| --- | --- | --- | --- |
| A | 1.79 / 1.75, clean 246 | 1.75 / 1.72, clean 253 | -0.04 / -0.03 |
| B-pre | 1.90 / 1.78, clean 267 | 1.89 / 1.76, clean 262 | -0.01 / -0.02 |

That is the panel's contribution, isolated for the first time: identical text, different judges,
0.01-0.04 on the aggregate. The gap between arms is stable under it (+0.14 / +0.04 on this panel,
+0.11 / +0.03 on the previous), so the frozen design gives the same headline as re-running A at
half the arm cost, with the sample noise removed from one side of the comparison.

Splits: A 58 fix / 61 no_harm, B-pre 40 / 75, B-post 36 / 71 of 372. Unanimous sub-2 for B-post:
fix 15, no_harm 49 (B-pre 14 / 36) - the no_harm rise is the 28 down-movers, and their notes are
the usual mix: an invented allowlist, a hardcoded fallback secret, a regex with no letters in it
rejecting every legitimate formula, a scheme check gated on `://` that `javascript:` never contains.

By source, guided pre -> post: `authored` (241) 1.90/1.78 -> 1.91/1.73;
`authored-top15-fix-complexity` (85) 1.85/1.67 -> 1.84/1.69; `juliet` (17) 1.73/1.69 -> 1.90/1.75;
`owasp-benchmark` (16) 2.00/1.96 -> 1.96/1.85. CWE-90 and CWE-416 are 2.00/2.00 for the guided arm
this sample (n=10, n=11); CWE-78 no_harm fell 1.67 -> 1.52 and CWE-862 1.61 -> 1.51, on the notes
above.

## What run 15 establishes

1. **A self-check instruction does not reduce name slips on Haiku.** 24 cases before, 24 after,
   24 in the arm that never saw it. The bucket is real and it is not reachable from SKILL.md prose;
   it needs a gate that runs the code - `javac`, `node --check`, `python -m py_compile`, `go vet` -
   or a stronger model. The SKILL.md addition is left in place as harmless but unearned; reverting it
   keeps the file thinner at no measured cost.
2. **The frozen control works.** Panel drift is measurable and small (-0.01 to -0.04); the arm gap
   survives it; 372 arm agents were not spent re-sampling noise.
3. **Fresh samples churn 49 of 372 cases by a point or more** with nothing changed that the model
   acted on. That is the floor any corpus-wide guided-arm aggregate has to clear, and it is why the
   per-case trace, not the table, carries every claim in this file.

## Limitations

- **B-post is one sample.** The self-check could have a small effect hidden under +-0.03; it cannot
  have the large one it was meant to have, because the target metric is unchanged to the case.
- **Whether the instruction was executed is inferred from the write-ups**, which the autonomous
  format does not require to show the check. A record field for the sourced-name list would make
  the next test direct.
- **Operational.** The first arm launch died with the session before any output (the working
  directory had drifted into `evals/`, so the agents' relative paths would have missed); relaunched
  from the root, all 372 in one pass. 37 nested outputs flattened and 60 empty directories removed
  before blinding. Judging (28 segments x 3) was interrupted twice by the session limit - 10, then
  52 of 84 valid on disk - and completed from the done-set; the workflow's own success tally
  undercounted the disk both times. Corpus and fixtures verified unchanged.
