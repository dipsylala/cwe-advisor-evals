# Validation harness - run 16 results

1116 write-ups judged (372 cases x 3 sets), **Haiku 4.5 guided arm, Sonnet 5 judges**, `must_preserve`
in the header. Frozen-control design as in run 15, and the first run under the bundled judging
protocol (HARNESS.md, **Bundled judging**). Three sets in one blind pool:

- **A** - the frozen unguided sample (run 13 + 14 composite), copied verbatim to `runs-v16/A`.
- **B-pre** - run 15's guided output (`runs-v15/B-post`), copied verbatim to `runs-v16/B-pre`.
- **B-post** - 372 fresh guided runs under the byte-identical run-11 prompt after one change:
  SKILL.md's Step 5 name check (commit `1907f00`) now says to copy the affected files to scratch,
  apply the fix there, and run `javac` / `node --check` / `go vet` / `php -l` / `py_compile` or the
  project build, falling back to the hand read only where no checker is reachable, and to report
  which check ran. The autonomous record gained a `verification` field for that.

Run 15 had shown that asking the model to *read* its fix as a compiler would changed nothing. This
run asks it to *run* the compiler, on a machine with `javac`, `node`, `go`, `php` and `dotnet` on
the path (no C/C++ compiler; `python` resolves to a Store shim).

## Answer: no effect, and one in five agents ran a checker at all

| Set | n | fix /2 | no-harm /2 | clean (2.00/2.00, all judges) |
| --- | --- | --- | --- | --- |
| A (frozen) | 372 | 1.74 | 1.67 | 230 |
| B-pre (frozen, run 15 guided) | 372 | 1.87 | 1.67 | 245 |
| B-post (fresh, compile instruction) | 372 | 1.84 | 1.66 | 241 |

B-post against B-pre on the same panel: -0.03 fix, -0.01 no_harm, -4 clean; 36 cases moved up by a
point or more and 37 moved down. The target metric is unchanged again - cases with a judge note
naming a non-existent, invented, or non-compiling identifier: **24 in B-pre, 25 in B-post.**

Compliance, from the 372 agent transcripts rather than the write-ups: **68 agents invoked a
compiler or checker** (Java 15, Python 15, PHP 16, Go 10, JavaScript 4, C/C++ 7, C# 1). On the
cases where one ran, the guided arm scored worse than its previous sample (B-pre 1.96/1.76 ->
B-post 1.83/1.74, name-slip cases 2 -> 6); on the 304 where none ran, level (1.84/1.64 -> 1.85/1.64,
22 -> 19). Two of the "ran" cases show what running looked like: `77/php/ChatbotCallUserFuncDispatch`
wrote its fix to a scratch file and never linted it, then shipped `const COMMAND_HANDLERS` inside a
function body - a PHP parse error (reproduced, php 8.5); `287/php/JwtDecodeLegacyArrayAlgorithmsForm`
ran `php -l` on the original case file instead of the fix, then shipped `new Key(...)` against a
`firebase/php-jwt` pinned to `^5.5`, where the class does not exist. The instruction was followed
as a gesture, not as a check.

The B-post name slips are the same shape as runs 13-15, now with a panel that compiles:
`http.CrossOriginProtection(router)` where that is a struct type (reproduced, `go doc`);
`const { parse } = require('expr-eval')` where 2.0.2 exports only `Expression` and `Parser`
(reproduced, npm); `DefaultJWTProcessor.processClaims()` where Nimbus exposes `process()`; a
`using System.Data` missing for `CommandType`; `catch (InternetAddress.AddressException e)` for a
top-level class; two `$"..."` interpolated strings concatenated into a `string` where
`ExecuteSqlInterpolatedAsync` needs a `FormattableString` (reproduced, dotnet, run 15).

## The panel changed, and that is the larger result

This is the first run judged from prepared bundles by the restricted `cwe-judge` agent. The frozen
sets measure what that did:

| Set | run 15 panel (old protocol) | run 16 panel (bundled, restricted) | drift |
| --- | --- | --- | --- |
| A | 1.75 / 1.72, clean 253 | 1.74 / 1.67, clean 230 | -0.01 / -0.05, -23 clean |
| B-pre | 1.89 / 1.73, clean 259 | 1.87 / 1.67, clean 245 | -0.02 / -0.06, -14 clean |

Identical text, stricter panel - and the strictness is of a specific kind. The old panel read; this
one builds. Judge notes carry `php -l`, `dotnet build`, `go build`, `javac` against real jars,
`npm install` of the named package, and they are finding compile errors the reading panel passed
(the s3 pilot in HARNESS.md caught two; this run's notes above are the same pattern at scale).
Every compile claim quoted in this file was reproduced independently before being believed. The
cost per scored write-up fell to roughly 37% of the old protocol's (billed-equivalent input
tokens, same 40 write-ups, three protocols measured); the runbook carries the numbers.

Two consequences. Run 16's table is not directly comparable to runs 11-15's except through the
frozen sets, which is what they are for: the arm gap (+0.13 / +0.00 here, +0.14 / +0.04 on the run-15
panel) survives the protocol change; the absolute level does not. And splits did not fall corpus-wide
(A 61/78, B-pre 44/71, B-post 43/72 of 372 - run 15's panel: 58/61, 40/75, 36/71); the pilot's
lower split rate was an n=40 artefact.

Panel-level audit of the 189 judge transcripts: 63 network-touching commands, all dependency
fetches for scratch compiles; three reads outside the bundle, each a judge re-reading its own
output. No `case.json`, no `cwe/`, no other judge's file, no web search.

## What run 16 establishes

1. **Telling Haiku to run the compiler does not make it run the compiler.** 18% did; of those,
   the two inspected ran it on the wrong artefact. Name slips 24 -> 25. Two SKILL.md instructions
   have now measured zero on this bucket; a third wording is not the experiment to run.
2. **The slip bucket needs a gate the model does not operate.** Harness-side: compile the fix
   before it is scored. Product-side: tooling that runs the checker for the model and feeds the
   diagnostic back, which is what the judges are now doing by hand and what the arm was asked to do
   and did not.
3. **Bundled, restricted judging is adopted.** Cheaper, and verifying by building rather than
   reading. The run-15 table and everything before it were scored by a panel that did not compile;
   the frozen sets are the bridge.

## Limitations

- **B-post is one sample** against one frozen prior sample; +-0.03 is inside the churn (73 of 372
  cases moved a point or more with nothing changed that the model acted on).
- **Compliance is inferred from transcripts** by matching compiler invocations in Bash commands;
  an agent that compiled through some other route is counted as not having run a checker.
- **The compile instruction leaves debris.** Agents wrote `Program.cs`, two `.csproj` files, an
  `obj/` tree and a `nul` file into the repository root and `__pycache__` into five case
  directories despite "a scratch location outside the codebase"; all removed before blinding,
  fixtures verified unchanged. `collect.py arm` now removes stray files under the arm tree; the
  repository root still needs a `git status` after any arm run.
- **Operational.** Arm: 372 in one pass plus one top-up for a case whose agent left no output
  and no journal entry; 38 nested outputs flattened, 83 empty directories removed, one nested
  duplicate that differed from the flat file (the later, complete one kept). Judging: 189 agents
  over three launches (55, 69, 63 valid per launch against the bundle index; the session limit took
  the rest each time), one JSON file with an unescaped backslash in a note repaired mechanically
  with scores untouched, one re-judged. The 42 old-protocol judge files from the abandoned first
  attempt are kept under `scores-v16/partial-old-protocol/` and are not in any aggregate.
