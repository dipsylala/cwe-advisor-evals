# Validation harness

Measures whether the knowledge base actually improves remediation, rather than assuming it does.

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

## Corpus

16 cases from [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), taken from
its `expectedresults-1.2.csv` ground truth and filtered to entries labelled a real vulnerability.
Test sources and labels are in `cases/` and `cases.json`.

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
`// SAST FINDING:` comment above the sink naming the CWE and the flow, and `cases.json` records the
same as structured metadata. Every arm receives it, so the comparison is purely about remediation
quality. Scoring the skill on whether it *finds* the bug would measure something it does not claim
to do, and would advantage the no-skill arm for the same reason.

## Arms

Each case is run three times, in a **fresh context** each time.

| Arm | Guidance supplied |
|---|---|
| **A** | None. The finding and the file, nothing else |
| **B** | The current `{CWE}/INDEX.md` and `{CWE}/java/INDEX.md` |
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
