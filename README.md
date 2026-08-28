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
3. Did removing the code blocks help or hurt? That A/B was proposed when the sweep was made and
   never run. The pre-sweep entries are still recoverable from git.

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
| Never reviewed | 327, 330, 501, 643 | 8 |

All are Java servlets, which holds language constant across arms and removes it as a confound.

## Arms

Each case is run three times, in a **fresh context** each time.

| Arm | Condition |
|---|---|
| **A** | Model alone. No skill, no knowledge base access |
| **B** | Skill as it currently stands |
| **C** | Skill with the entry restored to its pre-sweep state (`git show 9a5a105^:{CWE}/INDEX.md` and the language file) |

Arm A is the control and the reason the exercise is worth running. Without it the numbers describe
the model, not the knowledge base.

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

Binary: **CWE correctly identified** - did the run route to the weakness the ground truth names.

**Primary metric:** proportion of cases scoring 2 on *Vulnerability removed*. Secondary: mean total
across the four criteria.

**Comparisons:** B vs A overall; B vs A split by reviewed/unreviewed; C vs B.

## Predictions

Recorded in advance so the result cannot be rationalised after the fact.

- B beats A on *Fit to the code* and on CWE identification, but the gap on *Vulnerability removed*
  is small - a capable model already fixes textbook SQL injection and XSS.
- The reviewed/unreviewed split shows a smaller difference than the review effort implies, because
  both arms share the same model and Benchmark's cases are close to textbook.
- C vs B is close to a wash, with the code blocks helping most where the fix has an awkward shape
  (CWE-89's `CallableStatement`, CWE-501's trust boundary) and hurting where a block would be
  copied verbatim into a context it does not fit.

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
