# Validation harness - run 3 results

51 runs (17 cases x 3 arms) on the run-2 Juliet corpus, scored blind by three judges who each
scored all 51. Scores are the mean across the three.

The question: run 2 showed the knowledge base's only measurable effect was on `no_harm` - whether
the fix breaks or silently changes something the original did. SKILL.md gained a sink-contract step
(Step 4) and a "changed only what it had to" check (Step 5), and the autonomous record gained a
`behaviour_changes` field. Did that work?

## Arms

| Arm | Condition |
|---|---|
| **A** | No skill, no guidance. Run-2 output, re-judged here |
| **B** | Skill as it stood in run 2, before the sink-contract change. Run-2 output, re-judged here |
| **B2** | Skill after the change. Run 3, fresh |

Arms A and B are re-judged rather than re-run, so all three sets are scored by the same judges in
one blind pool. B2's outputs carry a `## Behaviour changes` section that A and B cannot have; it is
stripped before blinding, since the section alone would identify the arm. What is scored is the
code each arm produced, not its self-report.

## Results

| Set | n | verdict correct | source /2 | fix /2 | no-harm /2 |
|---|---|---|---|---|---|
| A - no guidance | 17 | 100% | 2.00 | 1.94 | 1.47 |
| B - skill, before | 17 | 100% | 2.00 | 2.00 | 1.76 |
| B2 - skill, after | 17 | 100% | 2.00 | 2.00 | **1.94** |

True positives only, where `no_harm` has variance:

| Set | n | no-harm /2 |
|---|---|---|
| A | 12 | 1.25 |
| B | 12 | 1.67 |
| B2 | 12 | **1.92** |

`no_harm` by CWE:

| CWE | A | B | B2 | entry text changed between B and B2? |
|---|---|---|---|---|
| CWE-78 | 1.25 | 1.25 | 1.75 | yes |
| CWE-89 | 2.00 | 2.00 | 2.00 | no |
| CWE-90 | 1.25 | 2.00 | 2.00 | no |
| CWE-601 | 1.25 | 1.75 | 2.00 | no |

## What the change did

**The CWE-601 column is the clean cell.** Its entry text is byte-identical between B and B2, so the
1.75 -> 2.00 move is attributable to the SKILL.md change alone. B's fixes rebuilt the redirect
target and dropped the URI fragment; B2's preserved it. That is the sink contract's "returns" item
doing exactly what it was written to do.

**CWE-78 improved but is confounded.** 1.00 -> 1.67 on true positives, but the entry itself was
rewritten between the two runs (commit `6a7d2d4`), so this cell measures the entry fix and the
workflow change together and cannot separate them. Two of the three cases now replace `exec` with
`Files.newDirectoryStream` **and deliberately discard the listing** to match the original's silent,
output-free behaviour - the precise failure run 1 and run 2 both recorded.

**One CWE-78 case still scores 1, and it fails on a contract item the step names.** All three judges
independently flagged the same thing: the fix closes the injection and preserves the output
contract, but `Paths.get(data)` is unguarded against null while the catch covers only
`InvalidPathException` and `IOException`, so a request with no `name` parameter now throws an
uncaught `NullPointerException` where the original returned quietly. "Failure behaviour" is the
fourth item in the Step 4 contract list. Naming a check does not make a model perform it.

**A separated on fix quality for the first time in three runs.** The unguided arm scored 1.94
rather than 2.00: its three CWE-601 fixes rebuilt the target from the *decoded* `uri.getPath()`, so
`/%2f%2fevil.example` re-emerges as `//evil.example` and can still yield a cross-origin `Location`.
Both guided arms used `getRawPath()`. This is a genuine hole in a fix that reads as correct, and it
is the first time in 133 scored runs that guidance has moved a criterion other than `no_harm`.

## Judge reliability

Judges determined exploitability themselves rather than being told. Their determination matched the
corpus ground truth on **51/51** runs. Across the three judges, all 51 agreed on `source_identified`,
48 of 51 on `fix_quality`, and 48 of 51 on `no_harm`; every `no_harm` disagreement was one judge
penalising a dropped URI fragment that the other two let pass.

## Limitations

- **Prompt drift between B and B2.** The run-2 runner prompt was not preserved verbatim, so B2's
  prompt is a reconstruction from the protocol description. The CWE-601 and CWE-78 outcomes are
  near-binary (is the fragment preserved, is the listing emitted) and unlikely to turn on prompt
  wording, but the comparison is not prompt-controlled.
- **Part of the treatment is in the prompt, not the skill.** B2's runners were asked for a
  `Behaviour changes` section. That matches autonomous mode, where the record carries the field -
  but interactive mode has no such record, and this run says nothing about whether the Step 5 check
  fires without one.
- **n = 17 per arm, four CWEs, one language.** Direction, not significance.
- **`no_harm` is now near its ceiling** at 1.92 on true positives. This corpus cannot measure much
  further improvement; a harder one would be needed.

## What runs 1-3 establish together

Three runs, 133 scored outputs. Verdict accuracy, source tracing and fix quality are saturated in
every arm including the unguided one, at chain depths up to five files. The knowledge base has
never improved detection. Its measurable contribution is entirely in not breaking things - and that
contribution is now positive and repeatable, where in run 2 it was mixed.
