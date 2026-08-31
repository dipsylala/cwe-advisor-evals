# Validation harness - run 1 results

48 runs (16 cases x 3 arms), scored blind by four judges against the rubric below, which was
committed before any run executed. Arm mapping was held outside the repository during scoring.

## Design (pre-registered before this run)

### Corpus

16 cases from [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), taken from
its `expectedresults-1.2.csv` ground truth and filtered to entries labelled a real vulnerability.

Chosen because they are **authored externally**. Cases written for this harness would be shaped
toward the guidance - unconsciously matching the vulnerability to the form the entry already
describes - which would manufacture whatever result was wanted.

| Group | CWEs | Cases |
|---|---|---|
| Reviewed by the top-15 pass | 22, 78, 79, 89 | 8 |
| Never reviewed | 90, 330, 614 | 8 |

Every CWE here has both a root entry and a `java/` entry, so each arm receives the same *shape* of
guidance and coverage depth is not confounded with review status. Three Benchmark categories were
excluded for that reason: CWE-327, CWE-501 and CWE-643 (XPath Injection) had no language file, or no
entry at all, at the time - a coverage gap this exercise surfaced. Since closed by the language-file
sweep recorded in TODO.md: CWE-501 and CWE-643 gained language entries in batch 28; CWE-327 remains
root-only.

All are Java servlets, which holds language constant across arms and removes it as a confound.

**Cases are presented as findings, not as raw code.** This advisor remediates; it does not detect.
A SAST tool or another skill supplies the finding, and SKILL.md is built for that - Step 1 takes
the CWE as given, and Step 4 prefers a tool-supplied taint path. Each case file therefore carries a
`// SAST FINDING:` comment above the sink naming the CWE and the flow, and its `case.json` records
the same as structured metadata. Every arm receives it, so the comparison is purely about
remediation quality. Scoring the skill on whether it *finds* the bug would measure something it
does not claim to do, and would advantage the no-skill arm for the same reason.

### Arms

Each case is run three times, in a **fresh context** each time.

| Arm | Guidance supplied |
|---|---|
| **A** | None. The finding and the file, nothing else |
| **B** | The current `cwe/{CWE}/INDEX.md` and `cwe/{CWE}/java/INDEX.md` |
| **C** | The same two files as of commit `9a5a105` - after the `Safe Pattern` sweep, before the top-15 review |

Arm A is the control and the reason the exercise is worth running. Without it the numbers describe
the model, not the knowledge base.

**The arms differ only in the guidance text.** Every arm receives the same task framing, the same
annotated case file, and the same instruction to produce a fix. SKILL.md's workflow is held
constant rather than invoked, because this run is about the *content* of the knowledge base:
mixing in the workflow would leave B vs C confounded between "fewer code blocks" and "different
routing". Testing the workflow itself - routing, mode selection, the false-positive exit - is a
separate exercise against different inputs (see run 2).

### Rubric

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

### Predictions

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

### Limitations

Stated because they bound what this run can support.

- **Benchmark cases are synthetic.** Auto-generated servlets with a consistent shape. They test
  whether a fix is correct, not whether it survives a real codebase's structure.
- **Sample is small.** 16 cases across 8 CWEs supports direction, not significance.
- **Scoring is judgement.** Deterministic checks are used where a case allows; the rest is rubric
  scoring, which is why it is done blind and against criteria fixed in advance.
- **Runs must originate in fresh contexts.** A judge or runner that has already read the knowledge
  base cannot credibly produce arm A.

## Headline: the harness could not discriminate

**Every one of the 48 runs scored 2 on the primary metric.** All three arms tied at 7.62/8 overall.
B vs A is +0.00. B vs C on reviewed CWEs is +0.00. The noise floor is 0.00.

A metric with no variance measures nothing, so **run 1 does not answer the question it was built to
answer**. What it does establish is why, and that is worth having before spending more on it.

The cause is the corpus. OWASP Benchmark's true positives are single-sink, textbook instances -
one tainted parameter, one obvious sink, in a 60-line servlet with no surrounding structure. A
capable model fixes all of them with or without guidance. The Limitations section above records them
as "synthetic," which turned out to understate it: they are not merely artificial, they are too easy
to separate any arm from any other.

## What did vary

All the variation landed in *functionality* and *fit* - whether the fix preserved what the endpoint
did, and whether it suited that sink. That is where the one real signal appeared.

### The guidance made one fix worse, and the mechanism is legible

On `BenchmarkTest00006` (CWE-78), arm B scored **0 for functionality and 0 for fit**: it deleted the
`ProcessBuilder` call and the result-printing entirely, so the endpoint stopped doing its job. Arm C
did the same thing less severely (fit 1). Arm A, with no guidance at all, kept the execution and
made it safe (fit 2).

This traces directly to how `78/java/INDEX.md` is written. Its guidance opens with "eliminate
`Runtime.exec()` and `ProcessBuilder` calls entirely", and five of its first six principles are
about removing process execution; "only use ProcessBuilder as a last resort with validated argument
lists" arrives sixth. For a finding where executing a command *is* the feature, that ordering reads
as "delete the feature", and an agent following it faithfully did exactly that.

n = 2 cases in one arm, so this is a hypothesis rather than a measurement. But the mechanism is
visible in the text, and it is the kind of harm a knowledge base can do that no amount of accuracy
review would catch: every claim in that entry is *true*, and the emphasis is still wrong for a
common class of finding.

### Shared failures, not guidance failures

Every arm invented procedure names (`listUsers`, `getUserCount`) when allowlisting the
`CallableStatement` procedure position in the CWE-89 cases, scoring 1 on functionality. Two arms
left the connection unclosed. These are model behaviours the guidance neither caused nor prevented.

## Results

`clean` = share scoring 2 on *Vulnerability removed* (the primary metric). `total` = mean of the four criteria summed, max 8.

| Set | n | clean | total | vuln | func | no-new | fit |
|---|---|---|---|---|---|---|---|
| A - no guidance | 16 | 100% | 7.62 | 2.00 | 1.69 | 2.00 | 1.94 |
| B - current | 16 | 100% | 7.62 | 2.00 | 1.75 | 2.00 | 1.88 |
| C - pre-review | 16 | 100% | 7.62 | 2.00 | 1.81 | 1.94 | 1.88 |

### Split by review status

| Set | n | clean | total | vuln | func | no-new | fit |
|---|---|---|---|---|---|---|---|
| reviewed / arm A | 8 | 100% | 7.50 | 2.00 | 1.62 | 2.00 | 1.88 |
| reviewed / arm B | 8 | 100% | 7.25 | 2.00 | 1.50 | 2.00 | 1.75 |
| reviewed / arm C | 8 | 100% | 7.25 | 2.00 | 1.62 | 1.88 | 1.75 |
| unreviewed / arm A | 8 | 100% | 7.75 | 2.00 | 1.75 | 2.00 | 2.00 |
| unreviewed / arm B | 8 | 100% | 8.00 | 2.00 | 2.00 | 2.00 | 2.00 |
| unreviewed / arm C | 8 | 100% | 8.00 | 2.00 | 2.00 | 2.00 | 2.00 |

### Key comparisons

- **B vs A (does the knowledge base beat the bare model):** total 7.62 vs 7.62 (+0.00), clean 100% vs 100%
- **B vs C on reviewed CWEs (the review effect):** total 7.25 vs 7.25 (+0.00)
- **B vs C on unreviewed CWEs (NOISE FLOOR - guidance is byte-identical):** total 8.00 vs 8.00 (+0.00)

The review effect (+0.00) **does NOT clear** the noise floor (0.00) measured on identical guidance.

### Per-case scores

| run | arm | CWE | group | case | vuln | func | no-new | fit | sink |
|---|---|---|---|---|---|---|---|---|---|
| R045 | A | 22 | reviewed | BenchmarkTest00001 | 2 | 2 | 2 | 2 | y |
| R007 | B | 22 | reviewed | BenchmarkTest00001 | 2 | 2 | 2 | 2 | y |
| R006 | C | 22 | reviewed | BenchmarkTest00001 | 2 | 2 | 2 | 2 | y |
| R002 | A | 22 | reviewed | BenchmarkTest00002 | 2 | 2 | 2 | 2 | y |
| R028 | B | 22 | reviewed | BenchmarkTest00002 | 2 | 2 | 2 | 2 | y |
| R004 | C | 22 | reviewed | BenchmarkTest00002 | 2 | 2 | 2 | 2 | y |
| R005 | A | 78 | reviewed | BenchmarkTest00006 | 2 | 1 | 2 | 2 | y |
| R008 | B | 78 | reviewed | BenchmarkTest00006 | 2 | 0 | 2 | 0 | y |
| R027 | C | 78 | reviewed | BenchmarkTest00006 | 2 | 1 | 2 | 1 | y |
| R033 | A | 78 | reviewed | BenchmarkTest00007 | 2 | 1 | 2 | 2 | y |
| R047 | B | 78 | reviewed | BenchmarkTest00007 | 2 | 1 | 2 | 2 | y |
| R043 | C | 78 | reviewed | BenchmarkTest00007 | 2 | 1 | 2 | 1 | y |
| R025 | A | 79 | reviewed | BenchmarkTest00013 | 2 | 2 | 2 | 2 | y |
| R009 | B | 79 | reviewed | BenchmarkTest00013 | 2 | 2 | 2 | 2 | y |
| R015 | C | 79 | reviewed | BenchmarkTest00013 | 2 | 2 | 2 | 2 | y |
| R040 | A | 79 | reviewed | BenchmarkTest00014 | 2 | 2 | 2 | 2 | y |
| R001 | B | 79 | reviewed | BenchmarkTest00014 | 2 | 2 | 2 | 2 | y |
| R039 | C | 79 | reviewed | BenchmarkTest00014 | 2 | 2 | 2 | 2 | y |
| R019 | A | 89 | reviewed | BenchmarkTest00008 | 2 | 1 | 2 | 1 | y |
| R034 | B | 89 | reviewed | BenchmarkTest00008 | 2 | 1 | 2 | 2 | y |
| R026 | C | 89 | reviewed | BenchmarkTest00008 | 2 | 1 | 2 | 2 | y |
| R003 | A | 89 | reviewed | BenchmarkTest00018 | 2 | 2 | 2 | 2 | y |
| R020 | B | 89 | reviewed | BenchmarkTest00018 | 2 | 2 | 2 | 2 | y |
| R010 | C | 89 | reviewed | BenchmarkTest00018 | 2 | 2 | 1 | 2 | y |
| R030 | A | 90 | unreviewed | BenchmarkTest00012 | 2 | 2 | 2 | 2 | y |
| R017 | B | 90 | unreviewed | BenchmarkTest00012 | 2 | 2 | 2 | 2 | y |
| R038 | C | 90 | unreviewed | BenchmarkTest00012 | 2 | 2 | 2 | 2 | y |
| R012 | A | 90 | unreviewed | BenchmarkTest00021 | 2 | 2 | 2 | 2 | y |
| R018 | B | 90 | unreviewed | BenchmarkTest00021 | 2 | 2 | 2 | 2 | y |
| R042 | C | 90 | unreviewed | BenchmarkTest00021 | 2 | 2 | 2 | 2 | y |
| R046 | A | 90 | unreviewed | BenchmarkTest00044 | 2 | 2 | 2 | 2 | y |
| R036 | B | 90 | unreviewed | BenchmarkTest00044 | 2 | 2 | 2 | 2 | y |
| R023 | C | 90 | unreviewed | BenchmarkTest00044 | 2 | 2 | 2 | 2 | y |
| R031 | A | 330 | unreviewed | BenchmarkTest00023 | 2 | 2 | 2 | 2 | y |
| R024 | B | 330 | unreviewed | BenchmarkTest00023 | 2 | 2 | 2 | 2 | y |
| R014 | C | 330 | unreviewed | BenchmarkTest00023 | 2 | 2 | 2 | 2 | y |
| R048 | A | 330 | unreviewed | BenchmarkTest00066 | 2 | 1 | 2 | 2 | y |
| R029 | B | 330 | unreviewed | BenchmarkTest00066 | 2 | 2 | 2 | 2 | y |
| R044 | C | 330 | unreviewed | BenchmarkTest00066 | 2 | 2 | 2 | 2 | y |
| R016 | A | 330 | unreviewed | BenchmarkTest00067 | 2 | 1 | 2 | 2 | y |
| R013 | B | 330 | unreviewed | BenchmarkTest00067 | 2 | 2 | 2 | 2 | y |
| R011 | C | 330 | unreviewed | BenchmarkTest00067 | 2 | 2 | 2 | 2 | y |
| R021 | A | 614 | unreviewed | BenchmarkTest00087 | 2 | 2 | 2 | 2 | y |
| R032 | B | 614 | unreviewed | BenchmarkTest00087 | 2 | 2 | 2 | 2 | y |
| R022 | C | 614 | unreviewed | BenchmarkTest00087 | 2 | 2 | 2 | 2 | y |
| R041 | A | 614 | unreviewed | BenchmarkTest00169 | 2 | 2 | 2 | 2 | y |
| R037 | B | 614 | unreviewed | BenchmarkTest00169 | 2 | 2 | 2 | 2 | y |
| R035 | C | 614 | unreviewed | BenchmarkTest00169 | 2 | 2 | 2 | 2 | y |


## What run 1 changes

1. **The corpus has to get harder.** Benchmark true positives cannot separate these arms. A useful
   v2 needs cases where the fix is contested: a legitimate feature that must survive the fix, a
   sink with no drop-in safe replacement, framework-specific traps, version-dependent APIs. Real
   CVE fix commits are the obvious source.
2. **Guidance should be tested for harm, not just for help.** The only signal in 48 runs was the
   knowledge base making an outcome *worse*. That direction was not something the rubric was built
   to look for, and it is the direction with the most to teach.
3. **The `78/java` emphasis problem is worth fixing on its own**, independent of any further eval.

## Honest accounting against the predictions

The predictions above said B would beat A on *fit* with a small gap on *vulnerability
removed*. B did not beat A anywhere: it tied overall and was marginally worse on the reviewed CWEs
(7.25 vs 7.50). The prediction that the review effect might not clear the noise floor was correct,
though not for the reason given - there was no effect and no noise to clear.

The Predictions section above also said "if B does not beat A anywhere, that is the finding, and it argues for
rewriting entries around what a model cannot infer". Run 1 cannot support that conclusion, because
it cannot distinguish "the knowledge base adds nothing" from "these cases are too easy to tell".
Both remain live.

