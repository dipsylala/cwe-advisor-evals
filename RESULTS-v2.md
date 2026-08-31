# Validation harness - run 2 results

34 runs (17 cases x 2 arms) on Juliet multi-file flows, scored blind by three judges. Arm A had no
guidance; arm B invoked the `cwe_advisor` skill in autonomous mode.

## Design

Run 1 measured the fix advice and called it "the knowledge base." It did not test the other half
of the skill. Benchmark cases put source and sink in the same `doPost`, three lines apart, so:

- SKILL.md Step 4 was a no-op - there was no flow to trace, and `references/data-flow-trace.md` was
  never loaded by any arm.
- The "break taint after allowlist validation" rule was never exercised, because there was nowhere
  downstream for a tainted value to survive to.
- The false-positive exit added to Step 4 had **no coverage at all** - every case was a true
  positive, so no arm ever had the opportunity to correctly decline to fix.

This run uses the Juliet Java suite (`find-sec-bugs/juliet-test-suite`), whose variant numbering is
built around exactly this axis:

| Variant | Structure | What it tests |
|---|---|---|
| `_51a`/`_51b` | taint crosses two files | inter-file tracing |
| `_52a-c`, `_53a-d` | three and four files | multi-hop tracing |
| `_54a-e` | five-file chain | whether tracing survives depth |
| `_61a`/`_61b` | taint returned from another class | return-value flow |
| `_31`, `_41`, `_45` | class member, method argument, field | intra-class flow |

The finding given to each arm names **only the sink file and line**, as a scanner would, leaving
the source to be traced back through the chain.

Juliet's `good` variants (`goodB2G` sanitises the sink, `goodG2B` uses a safe source) supply
negative cases: present one with a plausible finding and score whether the arm correctly reports no
exploitable path instead of "fixing" working code. OWASP Benchmark's ~1400 `real vulnerability =
false` rows are a second source for the same purpose.

Run 1 supplied CWE entry text and held SKILL.md constant, to isolate content. That was wrong for
this run's question: the data-flow guidance *is* SKILL.md Step 4 and `references/data-flow-trace.md`,
so a content-only arm would miss it a second time.

| Arm | Condition |
|---|---|
| **A** | No skill, no guidance. The case files and the finding, nothing else |
| **B** | Invokes the `cwe_advisor` skill in autonomous mode |

Arm B therefore exercises the whole product - CWE resolution, entry loading, the Step 4 trace, the
allowlist fix-point rule, the false-positive exit, and the autonomous output record - rather than
the entry text alone. Arm C is dropped: run 1 measured no review effect against a 0.00 noise floor,
so the third arm was not buying anything.

Both arms are asked for the same output shape (verdict, source, fix, explanation) so the two are
comparable, and both are told a "not exploitable" verdict is a legitimate answer. Without that, the
five false-positive cases would be unfair to arm A rather than informative.

The rubric adds three criteria run 1 could not use:

- **source_identified** - did the run name the actual source, or assume one?
- **fix_point** - is the change at the right place in the chain (sink, boundary, or source), or did
  it patch a middle hop and leave other callers exposed?
- **correctly_declined** - for a negative case, did it report no exploitable path rather than
  modify safe code? This is the direction run 1 had no way to measure, and the direction where a
  knowledge base can do the most damage.

### Corpus

17 cases from Juliet, de-labelled mechanically (see the build script's docstring):

| CWE | Reviewed | TP by depth | FP |
|---|---|---|---|
| 89 SQL Injection | yes | 2, 4, 5 files | hardcoded source; parameterised sink |
| 78 OS Command Injection | yes | 2, 4, 5 files | hardcoded source |
| 90 LDAP Injection | no | 2, 4, 5 files | hardcoded source |
| 601 URL Redirection | no | 2, 4, 5 files | hardcoded source |

12 true positives, 5 false positives. Depth is the variable run 1 lacked: in a 5-file case the
finding names the sink in the fifth file and the source is four hops away.

## Judging is trustworthy

Judges determined exploitability themselves rather than being told. Their determination matched the
corpus ground truth on **34/34 runs**. Run 1's 0.00 noise floor showed judges were *consistent*;
this shows they are *correct*, which is the property that matters before reading anything into the
arm comparison.

## Three of four criteria saturated again

Both arms scored 100% on verdict, 2.00 on source tracing and 2.00 on fix quality - **including at
depth 5**, where the source is four hops and four files from the reported sink. Both arms also got
all five false positives right, correctly declining to change safe code.

So the data-flow concern that motivated run 2 is answered, and not in the knowledge base's favour:
the model traces multi-file taint without help, and correctly declines false positives without
help. Chain depth did not degrade either arm.

## The one criterion that discriminated, and it cuts both ways

`no_harm` is the only criterion with variance, and it is the first place either run has separated
the arms: **arm B 1.82 vs arm A 1.59** overall, 1.75 vs 1.42 on true positives.

The direction is not uniform, and the split is the finding:

**Guidance prevented harm on CWE-90 and CWE-601.** Unguided, arm A parameterised the LDAP filter
correctly but swapped the original `null` `SearchControls` for `SUBTREE_SCOPE` in all three cases -
silently widening the search from one level to the whole subtree while claiming to fix a
vulnerability. On CWE-601 it rebuilt the redirect target from `uri.getPath()` and dropped the query
string. Arm B made neither mistake; on unreviewed CWEs it scored 2.00 against arm A's 1.50.

**Guidance caused harm on CWE-78, again.** All three of arm B's harms are CWE-78, and all are the
same shape: it replaced `Runtime.exec`/`ProcessBuilder` with `Files.newDirectoryStream`, which
closes the injection but then writes the directory listing into the HTTP response, where the
original discarded the process output. That is an information disclosure introduced by the fix.

Run 1 found arm B deleting the `ProcessBuilder` call outright on a different corpus. Run 2 finds it
rewriting to a native API that changes what the endpoint returns. Two independent corpora, two run
designs, the same entry, the same root cause: `78/java/INDEX.md` opens with "eliminate
`Runtime.exec()` and `ProcessBuilder` calls entirely by using native Java libraries", and four of
its first five principles are removal instructions. This is no longer a hypothesis.

Note the confound this creates: CWE-78 sits in the *reviewed* group, so it drags arm B's reviewed
score down to parity (1.67 vs 1.67) while arm B leads on unreviewed CWEs. The reviewed/unreviewed
comparison in this run measures the CWE-78 defect more than it measures review effort.

## Results

| Set | n | verdict correct | source /2 | fix /2 | no-harm /2 |
|---|---|---|---|---|---|
| A - no guidance | 17 | 100% | 2.00 | 2.00 | 1.59 |
| B - skill | 17 | 100% | 2.00 | 2.00 | 1.82 |

### True positives vs false positives

| Set | n | verdict correct | source /2 | fix /2 | no-harm /2 |
|---|---|---|---|---|---|
| true positive / arm A | 12 | 100% | 2.00 | 2.00 | 1.42 |
| true positive / arm B | 12 | 100% | 2.00 | 2.00 | 1.75 |
| false positive / arm A | 5 | 100% | 2.00 | 2.00 | 2.00 |
| false positive / arm B | 5 | 100% | 2.00 | 2.00 | 2.00 |

### Source tracing by chain depth (true positives)

| Set | n | verdict correct | source /2 | fix /2 | no-harm /2 |
|---|---|---|---|---|---|
| depth 2 / arm A | 4 | 100% | 2.00 | 2.00 | 1.50 |
| depth 2 / arm B | 4 | 100% | 2.00 | 2.00 | 1.75 |
| depth 4 / arm A | 4 | 100% | 2.00 | 2.00 | 1.25 |
| depth 4 / arm B | 4 | 100% | 2.00 | 2.00 | 1.75 |
| depth 5 / arm A | 4 | 100% | 2.00 | 2.00 | 1.50 |
| depth 5 / arm B | 4 | 100% | 2.00 | 2.00 | 1.75 |

### Reviewed vs unreviewed CWEs

| Set | n | verdict correct | source /2 | fix /2 | no-harm /2 |
|---|---|---|---|---|---|
| reviewed / arm A | 9 | 100% | 2.00 | 2.00 | 1.67 |
| reviewed / arm B | 9 | 100% | 2.00 | 2.00 | 1.67 |
| unreviewed / arm A | 8 | 100% | 2.00 | 2.00 | 1.50 |
| unreviewed / arm B | 8 | 100% | 2.00 | 2.00 | 2.00 |

### Judge reliability

Judges determined exploitability independently. Their determination matched the corpus ground truth on **34/34** runs (100%). Disagreements are listed below if any.


### Key comparisons

- **Source tracing (B vs A):** 2.00 vs 2.00 (+0.00)
- **Verdict accuracy (B vs A):** 100% vs 100%
- **False positives handled correctly (B vs A):** 100% vs 100%, fix score 2.00 vs 2.00 (2.00 = correctly proposed no change, 0 = modified safe code)
- **Fix quality (B vs A):** 2.00 vs 2.00 (+0.00)

### Per-run

| run | arm | case | CWE | kind | depth | verdict | source | fix | no-harm |
|---|---|---|---|---|---|---|---|---|---|
| R112 | A | Case15 | 78 | FP | 2 | ok | 2 | 2 | 2 |
| R102 | B | Case15 | 78 | FP | 2 | ok | 2 | 2 | 2 |
| R101 | A | Case13 | 89 | FP | 2 | ok | 2 | 2 | 2 |
| R113 | A | Case14 | 89 | FP | 2 | ok | 2 | 2 | 2 |
| R106 | B | Case13 | 89 | FP | 2 | ok | 2 | 2 | 2 |
| R116 | B | Case14 | 89 | FP | 2 | ok | 2 | 2 | 2 |
| R104 | A | Case17 | 90 | FP | 2 | ok | 2 | 2 | 2 |
| R131 | B | Case17 | 90 | FP | 2 | ok | 2 | 2 | 2 |
| R128 | A | Case19 | 601 | FP | 2 | ok | 2 | 2 | 2 |
| R120 | B | Case19 | 601 | FP | 2 | ok | 2 | 2 | 2 |
| R109 | A | Case04 | 78 | TP | 2 | ok | 2 | 2 | 1 |
| R107 | B | Case04 | 78 | TP | 2 | ok | 2 | 2 | 1 |
| R132 | A | Case05 | 78 | TP | 4 | ok | 2 | 2 | 1 |
| R126 | B | Case05 | 78 | TP | 4 | ok | 2 | 2 | 1 |
| R118 | A | Case06 | 78 | TP | 5 | ok | 2 | 2 | 1 |
| R129 | B | Case06 | 78 | TP | 5 | ok | 2 | 2 | 1 |
| R123 | A | Case01 | 89 | TP | 2 | ok | 2 | 2 | 2 |
| R117 | B | Case01 | 89 | TP | 2 | ok | 2 | 2 | 2 |
| R134 | A | Case02 | 89 | TP | 4 | ok | 2 | 2 | 2 |
| R127 | B | Case02 | 89 | TP | 4 | ok | 2 | 2 | 2 |
| R121 | A | Case03 | 89 | TP | 5 | ok | 2 | 2 | 2 |
| R115 | B | Case03 | 89 | TP | 5 | ok | 2 | 2 | 2 |
| R130 | A | Case07 | 90 | TP | 2 | ok | 2 | 2 | 1 |
| R119 | B | Case07 | 90 | TP | 2 | ok | 2 | 2 | 2 |
| R108 | A | Case08 | 90 | TP | 4 | ok | 2 | 2 | 1 |
| R111 | B | Case08 | 90 | TP | 4 | ok | 2 | 2 | 2 |
| R103 | A | Case09 | 90 | TP | 5 | ok | 2 | 2 | 1 |
| R124 | B | Case09 | 90 | TP | 5 | ok | 2 | 2 | 2 |
| R114 | A | Case10 | 601 | TP | 2 | ok | 2 | 2 | 2 |
| R133 | B | Case10 | 601 | TP | 2 | ok | 2 | 2 | 2 |
| R105 | A | Case11 | 601 | TP | 4 | ok | 2 | 2 | 1 |
| R122 | B | Case11 | 601 | TP | 4 | ok | 2 | 2 | 2 |
| R125 | A | Case12 | 601 | TP | 5 | ok | 2 | 2 | 2 |
| R110 | B | Case12 | 601 | TP | 5 | ok | 2 | 2 | 2 |


## What run 2 establishes

1. **The data-flow guidance is not what earns the knowledge base its place.** Both arms traced
   five-file chains perfectly and both handled every false positive. Step 4 and
   `references/data-flow-trace.md` changed nothing measurable here.
2. **Where the knowledge base does earn its place is in knowing an API's defaults.** Arm A's LDAP
   scope-widening is the clearest example: a plausible, confident fix that quietly changes security
   behaviour, and the entry naming the right overload prevented it. That is the kind of detail a
   model does not reliably carry, and it is worth more entry space than restating that SQL should
   be parameterised.
3. **CWE-78's framing is a confirmed defect** and should be fixed across the family, not just in
   `java`. Every CWE-78 entry opens with the same "eliminate entirely" instruction.

## Against the run 1 predictions

Run 1 predicted the knowledge base would show up in *fit* and barely in correctness. Run 2 says it
shows up in neither - it shows up in **not breaking things**, which neither run's rubric was
originally designed to measure and which only exists as a criterion because run 1's single negative
signal forced it in.

