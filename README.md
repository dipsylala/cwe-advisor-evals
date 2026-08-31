# Validation harness

Measures whether the knowledge base actually improves remediation, rather than assuming it does.

This file covers what is measured and what past runs found. To execute a run, see
[HARNESS.md](HARNESS.md) - the runbook, with the arm and judge prompts verbatim.

Nothing in this repository has been measured. The top-15 review, the `Safe Pattern` sweep that
removed 307 code blocks, the CWE-306 language entries and the version pass were all applied on
reasoning alone. This harness exists to put numbers against three open questions:

1. Does the knowledge base beat the bare model? If a capable model fixes SQL injection just as well
   without the entry, the entry is not earning its place, and the content should shift toward the
   detail a model genuinely lacks.
2. Does review effort show up in output quality? Cases are split between CWEs the top-15 review
   covered and CWEs it never touched.
3. Does the top-15 review show up in fix quality? Arm C is each entry as it stood *before* this
   session's review, so B vs C is a before/after on the same entry rather than a comparison across
   different CWEs of differing difficulty.

## Test cases

One tree, keyed by CWE and language the same way the knowledge base is, so a case sits next to the
guidance it exercises:

```text
cases/
  {CWE}/
    {language}/
      {case-id}/
        *.java        the case files
        case.json     metadata and the finding handed to each arm
```

Cases accumulate here rather than being versioned into a new directory per run - git holds the
history. Run records under `runs*/` name cases by id, so ids are stable once published.

Current contents: 106 cases across 17 CWEs and six languages. Four sources:

| `source` | n | What it is |
|---|---|---|
| `owasp-benchmark` | 16 | Single-file Java servlets, labels from `expectedresults-1.2.csv` |
| `juliet` | 17 | Java multi-file flow variants, de-labelled mechanically; taint crosses 2, 4 or 5 files |
| `authored-from-docs-pitfall` | 13 | Single-function cases across Java, Python, Go, C#, JavaScript and PHP, each built around a fix that looks right and is not |
| `authored` | 60 | Single-function, single-language, plain true-positive cases with no `trap`/`must_preserve`/`origin` - pure language-coverage for CWEs the corpus already had in one language, not a discrimination instrument |

The `authored` cases are a per-language coverage campaign, not a one-off: the goal is at least one case
per `(CWE, language)` slot that has a language-specific entry (318 slots were missing when the
campaign started; root-only CWEs with no language subfolder are out of scope - see TODO.md). Each
was written by a workflow agent that read the target `cwe/{CWE}/{language}/INDEX.md`'s own `Taint
Sinks` list and picked a real API from it, then had its `sink_line`/`sink_code` checked against the
file it actually wrote before being accepted. CWE-22, 78, 89, 90, 117, 209, 326, 330, 338, 347,
434, 502, 611 and 614 are fully covered across every language their entry has as of this writing;
TODO.md tracks what remains.

The third group exists because runs 1-3 measured the first two to saturation. Chain depth never
discriminated - every arm traced five-file chains perfectly, unguided included - while every
recorded harm was sink-local: output the original discarded, an argument the original left `null`,
a dropped URI fragment. These cases therefore drop the chain and vary what actually separated the
arms: how much contract the sink has, and how wrong the plausible fix is.

Run 4 scored the first 10 of these and found the traps mostly did not work (19/20 at ceiling on
`fix_quality`) - see [RESULTS-v4.md](RESULTS-v4.md). The one exception, `LogForgeOnFailure`
(CWE-117), confirmed a specific shape: when an entry's `Remediation Steps` open with an
infrastructure or configuration change rather than the fix at the reported sink, the guided arm
tends to perform that change and leave the flagged line untouched. `OrderEventQueueDeserialize`
(CWE-502/java), `ModelCachePickleLoad` (CWE-502/python), and `DeprecatedEntityLoaderGuard`
(CWE-611/php) target that same shape - each entry's leading remediation step is a migration or a
config call that does not touch the flagged sink, and in two cases performing it as written breaks
a real cross-service or cross-version contract the case's `must_preserve` field states. Extending
the batch in any other style is not expected to add resolution, per run 4's conclusion.

Each one is built from a `Common Pitfalls` bullet in the `docs/` corpus, which has been through
actor/critic review across two model families. Being authored here rather than externally sourced,
they carry two extra fields so the intended difficulty is explicit and checkable rather than
implied by the code:

- **`trap`** - the plausible fix that does not close the finding, or closes it while breaking
  something.
- **`must_preserve`** - the sink's contract a correct fix has to keep. This is what `no_harm` is
  scored against, rather than left to a judge's reading of the original.
- **`origin`** - the `docs/` pitfall the case is built from.

Their labels are an authoring claim, not an external ground truth, which is weaker than the other
two sources. Treat a judge disagreeing with `kind` on one of these as a finding about the case.

### Adding a case

Create `cases/{CWE}/{language}/{case-id}/` with the source files and a `case.json`:

| Field | Meaning |
|---|---|
| `id` | Directory name. Stable once a run has referenced it |
| `cwe`, `language` | Match the directory position |
| `source` | Where the case came from, for judging independence from the guidance |
| `kind` | `true_positive` or `false_positive` |
| `depth` | Files in the call chain from source to sink |
| `group` | `reviewed` or `unreviewed`, for the review-effort split |
| `files` | Source files, in call order |
| `finding` | What the scanner reports: `cwe`, `name`, `file`, `sink_line`, `sink_code`, `summary` |
| `trap`, `must_preserve`, `origin` | `authored-from-docs-pitfall` only - see above. A plain `authored` case (language-coverage, no deliberate wrong-fix) omits all three |

`case.json` holds the answer, so **runners and judges must be told not to read it**, the same way
they are told not to read `RESULTS*.md` or the `runs*/` directories. Everything an arm is entitled
to see is handed to it in the prompt: the case directory, the CWE, and the sink file and line.

Two properties matter more than volume. **Cases must be externally authored or independently
derived** - a case written against the guidance takes the shape the guidance already describes and
manufactures whatever result was wanted. And **ground truth must come from outside the case**:
Benchmark ships `expectedresults-1.2.csv`, Juliet encodes it in the variant name. A case whose
label is only an assertion in its own metadata cannot settle a disagreement with a judge.

## Corpus (run 1)

16 cases from [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), taken from
its `expectedresults-1.2.csv` ground truth and filtered to entries labelled a real vulnerability.
These now live in the shared case tree described under **Test cases** below, alongside the Juliet cases added for run 2.

Chosen because they are **authored externally**. Cases written here would be written toward the
guidance - unconsciously shaped so the vulnerability takes the form the entry already describes -
which would manufacture whatever result was wanted.

| Group | CWEs | Cases |
|---|---|---|
| Reviewed by the top-15 pass | 22, 78, 79, 89 | 8 |
| Never reviewed | 90, 330, 614 | 8 |

Every CWE here has both a root entry and a `java/` entry, so each arm receives the same *shape* of
guidance and coverage depth is not confounded with review status. Three Benchmark categories were
excluded for that reason: CWE-327 and CWE-501 have root guidance but no language file, and CWE-643
(XPath Injection) has no entry at all - a coverage gap this exercise surfaced, now recorded in
TODO.md.

All are Java servlets, which holds language constant across arms and removes it as a confound.

**Cases are presented as findings, not as raw code.** This advisor remediates; it does not detect.
A SAST tool or another skill supplies the finding, and SKILL.md is built for that - Step 1 takes
the CWE as given, and Step 4 prefers a tool-supplied taint path. Each case file therefore carries a
`// SAST FINDING:` comment above the sink naming the CWE and the flow, and its `case.json` records
the same as structured metadata. Every arm receives it, so the comparison is purely about remediation
quality. Scoring the skill on whether it *finds* the bug would measure something it does not claim
to do, and would advantage the no-skill arm for the same reason.

## Arms

Each case is run three times, in a **fresh context** each time.

| Arm | Guidance supplied |
|---|---|
| **A** | None. The finding and the file, nothing else |
| **B** | The current `cwe/{CWE}/INDEX.md` and `cwe/{CWE}/java/INDEX.md` |
| **C** | The same two files as of commit `9a5a105` - after the `Safe Pattern` sweep, before this session's review |

Arm A is the control and the reason the exercise is worth running. Without it the numbers describe
the model, not the knowledge base.

**The arms differ only in the guidance text.** Every arm receives the same task framing, the same
annotated case file, and the same instruction to produce a fix. SKILL.md's workflow is held
constant rather than invoked, because all three questions above are about the *content* of the
knowledge base: mixing in the workflow would leave B vs C confounded between "fewer code blocks"
and "different routing". Testing the workflow itself - routing, mode selection, the false-positive
exit - is a separate exercise against different inputs.

Runs are written to `runs/{arm}/{test}.md` containing the proposed fix and nothing identifying the
arm, so scoring can be done blind.

## Rubric

**Fixed before any run was executed.** Four criteria, scored 0-2, plus one binary.

| Criterion | 0 | 1 | 2 |
|---|---|---|---|
| **Vulnerability removed** | Original vector still works | Some paths closed, others open | Vector closed |
| **Functionality preserved** | Will not compile, or breaks the endpoint | Compiles but changes observable behaviour | Behaviour preserved |
| **No new weakness** | Introduces a different weakness | Questionable construct, not clearly exploitable | Clean |
| **Fit to the code** | Generic advice, or the wrong shape for this sink | Workable but not idiomatic | Right API, matches surrounding style |

Binary: **Flagged sink addressed** - did the change land on the data flow the finding names,
rather than on adjacent code.

**Primary metric:** proportion of cases scoring 2 on *Vulnerability removed*. Secondary: mean total
across the four criteria.

**Comparisons:** B vs A overall; B vs A split by reviewed/unreviewed; B vs C on the four reviewed
CWEs.

**Built-in noise floor.** The review never touched CWE-327, 330, 501 or 643, so for those 8 cases
arm C's guidance is byte-identical to arm B's. Any B-vs-C difference there is run-to-run variance
in the model and the judge, and it sets the bar a difference on the reviewed CWEs has to clear
before it means anything.

## Predictions

Recorded in advance so the result cannot be rationalised after the fact.

- B beats A on *Fit to the code*, but the gap on *Vulnerability removed* is small - a capable model
  already fixes textbook SQL injection and XSS.
- The reviewed/unreviewed split shows a smaller difference than the review effort implies, because
  both arms share the same model and Benchmark's cases are close to textbook.
- B vs C on the reviewed CWEs is positive but small, and may not clear the noise floor the
  identical-guidance pairs establish. The review corrected accuracy more than it changed the shape
  of the advice, and Benchmark's cases are close enough to textbook that accuracy corrections
  (the `th:attr` claim, the `Parameters.Add` value assignment) may never be exercised.

If B does not beat A anywhere, that is the finding, and it argues for rewriting entries around
what a model cannot infer - version floors, advisory status, framework-specific traps - and
dropping what it restates.

## Limitations

Stated because they bound what any result here can support.

- **Benchmark cases are synthetic.** Auto-generated servlets with a consistent shape. They test
  whether a fix is correct, not whether it survives a real codebase's structure.
- **Sample is small.** 16 cases across 8 CWEs supports direction, not significance.
- **Scoring is judgement.** Deterministic checks are used where a case allows; the rest is rubric
  scoring, which is why it is done blind and against criteria fixed in advance.
- **Runs must originate in fresh contexts.** A judge or runner that has already read the knowledge
  base cannot credibly produce arm A.

## Run 2 design (not yet executed)

Run 1 measured the fix advice and called it "the knowledge base". It did not test the other half
of the skill. Benchmark cases put source and sink in the same `doPost`, three lines apart, so:

- SKILL.md Step 4 is a no-op - there is no flow to trace, and `references/data-flow-trace.md` was
  never loaded by any arm.
- The "break taint after allowlist validation" rule was never exercised, because there is nowhere
  downstream for a tainted value to survive to.
- The false-positive exit added to Step 4 has **no coverage at all** - every case was a true
  positive, so no arm ever had the opportunity to correctly decline to fix.

Run 2 should use the Juliet Java suite (`find-sec-bugs/juliet-test-suite`), whose variant numbering
is built around exactly this axis:

| Variant | Structure | What it tests |
|---|---|---|
| `_51a`/`_51b` | taint crosses two files | inter-file tracing |
| `_52a-c`, `_53a-d` | three and four files | multi-hop tracing |
| `_54a-e` | five-file chain | whether tracing survives depth |
| `_61a`/`_61b` | taint returned from another class | return-value flow |
| `_31`, `_41`, `_45` | class member, method argument, field | intra-class flow |

The finding given to each arm should name **only the sink file and line**, as a scanner would,
leaving the source to be traced back through the chain.

Juliet's `good` variants (`goodB2G` sanitises the sink, `goodG2B` uses a safe source) supply the
missing negative cases: present one with a plausible finding and score whether the arm correctly
reports no exploitable path instead of "fixing" working code. OWASP Benchmark's ~1400
`real vulnerability = false` rows are a second source for the same purpose.

The rubric needs three additions for run 2, none of which run 1 could have used:

- **source_identified** - did the run name the actual source, or assume one?
- **fix_point** - is the change at the right place in the chain (sink, boundary, or source), or
  did it patch a middle hop and leave other callers exposed?
- **correctly_declined** - for a negative case, did it report no exploitable path rather than
  modify safe code? This is the direction run 1 had no way to measure, and the direction where a
  knowledge base can do the most damage.

## Run 2 arms (as executed)

Run 1 supplied CWE entry text and held SKILL.md constant, to isolate content. That was wrong for
run 2's question: the data-flow guidance *is* SKILL.md Step 4 and `references/data-flow-trace.md`,
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
comparable, and both are told a "not exploitable" verdict is a legitimate answer. Without that,
the five false-positive cases would be unfair to arm A rather than informative.

### Corpus (run 2 additions)

17 cases from Juliet, de-labelled mechanically (see the build script's docstring):

| CWE | Reviewed | TP by depth | FP |
|---|---|---|---|
| 89 SQL Injection | yes | 2, 4, 5 files | hardcoded source; parameterised sink |
| 78 OS Command Injection | yes | 2, 4, 5 files | hardcoded source |
| 90 LDAP Injection | no | 2, 4, 5 files | hardcoded source |
| 601 URL Redirection | no | 2, 4, 5 files | hardcoded source |

12 true positives, 5 false positives. Depth is the variable run 1 lacked: in a 5-file case the
finding names the sink in the fifth file and the source is four hops away.

## Run 3 (as executed)

Run 2 left one criterion with variance - `no_harm` - and split it both ways: guidance prevented
harm on CWE-90 and CWE-601, and caused it on CWE-78. Run 3 tests the response to that.

Changes under test, all in the shared path rather than in any entry:

- SKILL.md Step 4 gained a sink-contract step: before writing a fix, record what the sink returns,
  what it **discards**, which arguments are left implicit or `null`, and its failure behaviour.
- SKILL.md Step 5 gained a check that accounts for every change that is not the sink itself.
- `references/autonomous-output.md` gained a `behaviour_changes` field, so the check lands in the
  record a CI consumer reads rather than only in interactive presentation.

| Arm | Condition |
|---|---|
| **A** | No skill, no guidance - run-2 output, re-judged |
| **B** | Skill before the change - run-2 output, re-judged |
| **B2** | Skill after the change - fresh |

Same 17 Juliet cases. A and B are re-judged rather than re-run so all three sets sit in one blind
pool under the same judges; B2's `Behaviour changes` section is stripped before blinding, because
A and B cannot have one and its presence would identify the arm.

Results in [RESULTS-v3.md](RESULTS-v3.md).

## Run 4 (as executed)

First run against the ten `authored-from-docs-pitfall` cases, and the first executed from
[HARNESS.md](HARNESS.md) rather than from a scratch directory. Arms A (no guidance) and B (skill),
true positives only - the finding is given as confirmed, so the arm remediates rather than
adjudicates, and `verdict` and `source_identified` drop out of the rubric.

Results in [RESULTS-v4.md](RESULTS-v4.md). Short version: the traps mostly did not work, and the
one that did caught the guided arm.
