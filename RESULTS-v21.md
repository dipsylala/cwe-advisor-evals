# Run 21 - Haiku 4.5 on both arms, judged beside run 20's Sonnet pair

The companion to [RESULTS-v20.md](RESULTS-v20.md): a fresh unguided (A) and guided (B) Haiku 4.5
pair on the same 372 cases, the same prompts, the same gate, and the same rubric, so the two runs
answer one question together - **does the knowledge base still help a stronger model, and where
does the help go?** Run 20 is Sonnet 5; this run is Haiku 4.5.

## The judge panel was split, and it does not change the answer

Run 21 was to be judged by Fable throughout, as run 20 was. The account's Fable capacity ran out
with 26 of the 50 bundle segments scored, and the run finished on Opus 5 (`claude-opus-5`).

Two things keep that from muddying the result. First, panels are homogeneous *per segment*: the
seven segments Fable had partly scored were re-judged in full by Opus rather than topped up, so
no write-up's three-judge mean blends two models. Second, the partial Fable files were kept
(`scores-v21-fable-partial/`), and they score the same write-ups Opus then scored - a calibration
set of 106 write-ups measured under both models rather than an assumption:

| | n | Fable | Opus | offset |
| --- | --- | --- | --- | --- |
| fix_quality | 106 | 1.80 | 1.83 | +0.03 |
| no_harm | 106 | 1.74 | 1.73 | -0.01 |

89 of the 106 get an identical `no_harm` mean; Opus is stricter on 10 and Fable on 7. The offset
is the size of ordinary panel drift on frozen text (0.03 in run 19), so the two panels pool.

`blind.py` shuffles arms across segments, so both arms meet both panels in proportion, and the
guided-versus-unguided delta can be read inside each panel separately. It is the same delta:

| Panel | write-ups | A `fix_quality` | B `fix_quality` | delta | A `no_harm` | B `no_harm` | delta |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fable (26 segments) | 403 | 1.75 | 1.89 | +0.14 | 1.68 | 1.67 | -0.01 |
| Opus (24 segments) | 341 | 1.73 | 1.86 | +0.13 | 1.65 | 1.72 | +0.07 |
| Pooled | 744 | 1.74 | 1.88 | +0.14 | 1.67 | 1.69 | +0.02 |

## Gate

| Arm | OK | FAIL | UNCHECKED | NO_FILES | Kinds of FAIL |
| --- | --- | --- | --- | --- | --- |
| A (unguided) | 344 | 16 | 11 | 1 | unresolved-member 7, unused 6, other 2, missing-import 1, unresolved-name 1 |
| B (guided) | 351 | 10 | 10 | 1 | unresolved-member 3, unused 2, unresolved-name 2, other 1, missing-import 1, signature 1 |

Guidance halves the Go "declared and not used" bucket and the invented-member bucket; what it
does not fix is the same handful of names every model invents (`ChatMessage.UserId`,
`Order.getUserId()`, `JexlSandbox` from the wrong package - the last one still, in the unguided
arm, on a case whose entry has named the package since run 17).

Six first-pass rows were package gaps under the triage rule and five resolved once the superset
carried the library the fix named: `exp4j`, `simpleeval`, `symfony/expression-language`, and
`System.Management`. One row is `UNCHECKED` for an environment reason worth recording: an
unguided fix hosts PowerShell through `System.Management.Automation`, whose package
(`Microsoft.PowerShell.SDK`) cannot coexist with the superset's pinned `System.Data.SqlClient`
(NU1605). The fix may well be right; this harness cannot say.

## Judged

| Arm | fix_quality | no_harm | clean | no_harm < 2 | judge splits |
| --- | --- | --- | --- | --- | --- |
| A (unguided) | 1.74 | 1.67 | 226 | 121 | 49 |
| B (guided) | 1.88 | 1.69 | 245 | 120 | 48 |

Paired per case: `fix_quality` guided ahead on 57, behind on 23, tied on 292; `no_harm` ahead on
68, behind on 64, tied on 240. Build line obeyed 26 of 26.

## The cross-model result

| Arm model | fix_quality | no_harm | build failures |
| --- | --- | --- | --- |
| Sonnet 5 (run 20) | 1.92 -> 1.94 | 1.70 -> 1.76 | 7 -> 3 |
| Haiku 4.5 (run 21) | 1.74 -> 1.88 | 1.67 -> 1.69 | 16 -> 10 |

**Guidance recovers most of the model gap on fix quality.** Unguided, Haiku trails Sonnet by 0.18
(1.74 against 1.92). Guided, it trails by 0.06 (1.88 against 1.94). On this corpus and this axis
the knowledge base is worth about two thirds of the distance between the two model tiers - which
is the strongest practical argument the harness has produced for the entries existing at all.

**Where the help goes depends on how much headroom the model has.** Sonnet's `fix_quality` is
saturated (343 of 372 cases tied between its arms), so its guidance gain shows up almost entirely
on `no_harm` and on the gate. Haiku has room on `fix_quality` and takes it there instead, while
its `no_harm` barely moves. The two runs are not in conflict: guidance supplies the right API for
the sink, which a weaker model needs and a stronger model mostly already knows, and it supplies
the contract discipline, which neither model has by default.

**`no_harm` is the axis neither model handles well.** Unguided, 1.70 and 1.67; guided, 1.76 and
1.69, against a ceiling of 2. Both panels apply the run-17 rubric pin strictly to any restriction
the fix adds and the contract did not ask for, and both models add such restrictions on their own.
That is now measured on three judge models and two arm models, and it is the same finding each
time: the remaining loss is not about closing vulnerabilities, it is about not changing anything
else while doing so.

## Where the entries earned their keep, and where they did not

Largest guided gains for Haiku, by CWE: CWE-117 `fix_quality` 1.00 to 2.00 (the run-19 sweep gave
the entry the concrete escape output form, and the arm stopped writing a switch that mapped every
control character back to itself), CWE-502 1.48 to 1.97 with `no_harm` 1.09 to 1.42 (the
format-preserving doctrine from run 12), CWE-90 1.80 to 2.00 on `fix_quality` and 1.40 to 1.93 on
`no_harm`, CWE-347 `no_harm`
1.17 to 1.67, CWE-614 1.71 to 2.00, CWE-77 1.79 to 1.98. By language the gains are broad: PHP
1.77 to 1.98, Python 1.75 to 1.94, Go 1.58 to 1.78, Java 1.73 to 1.87.

Where guidance still costs `no_harm`: CWE-78 (1.56 to 1.42) and CWE-77 (1.71 to 1.54), the same
shell-and-library-replacement families that have resisted three rounds of edits, now with the
losses being genuine semantic changes rather than the allowlists the run-18 doctrine change
removed - a return value that becomes `True` instead of the server's bytes, a `grep` stream
replaced by a whole-file read, an unused `ctx` that drops request cancellation. CWE-434 (1.63 to
1.49) and CWE-94 (three build failures in both arms) are unchanged from run 19's reading.

One entry-attributable regression, and it is from the run-19 sweep: `cwe/22`'s tightened wording
produced redundant `..` and `IsAbs` rejections in Go and Java on cases where the containment check
already covered it. The sweep removed that shape from the entries and the arm reintroduced it from
its own priors; the entry text is not the lever there.

## Limitations

- One sample per arm. The per-CWE rows with fewer than ten cases are direction only, and Perl
  (four cases) moved 2.00 to 1.75 on a single write-up.
- Two judge panels, pooled on a measured offset of +0.03 on `fix_quality` and -0.01 on `no_harm`.
  Comparisons against runs 17-19
  (Sonnet judges) are still not available at the level of absolute numbers.
- The gate reflects one dependency environment per language, and one unguided write-up is
  unjudgeable by it for the NU1605 reason above.
- The cross-model comparison shares a corpus that has been edited against Haiku's failures for
  three runs. That biases *against* the finding for Sonnet, not for it, but it is not a neutral
  corpus for either model.

## Cost

Arms: 744 Haiku agents, 31.3M tokens across the original launch and three resumes (two session
limits, one interrupt). Gate: minutes, no tokens, run in two serial chains. Judges: 150 agents -
78 Fable, 72 Opus - about 10.5M tokens. Four judge files carried invalid JSON escapes in quoted
code and were repaired mechanically without touching a score
(`scratchpad/repair_judge_json.py`).
