# Validation harness - run 1 results

48 runs (16 cases x 3 arms), scored blind by four judges against the rubric in README.md, which
was committed before any run executed. Arm mapping was held outside the repository during scoring.

## Headline: the harness could not discriminate

**Every one of the 48 runs scored 2 on the primary metric.** All three arms tied at 7.62/8 overall.
B vs A is +0.00. B vs C on reviewed CWEs is +0.00. The noise floor is 0.00.

A metric with no variance measures nothing, so **run 1 does not answer the question it was built to
answer**. What it does establish is why, and that is worth having before spending more on it.

The cause is the corpus. OWASP Benchmark's true positives are single-sink, textbook instances -
one tainted parameter, one obvious sink, in a 60-line servlet with no surrounding structure. A
capable model fixes all of them with or without guidance. The limitation recorded in README.md as
"synthetic" turned out to understate it: they are not merely artificial, they are too easy to
separate any arm from any other.

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

The predictions in README.md said B would beat A on *fit* with a small gap on *vulnerability
removed*. B did not beat A anywhere: it tied overall and was marginally worse on the reviewed CWEs
(7.25 vs 7.50). The prediction that the review effect might not clear the noise floor was correct,
though not for the reason given - there was no effect and no noise to clear.

The README also said "if B does not beat A anywhere, that is the finding, and it argues for
rewriting entries around what a model cannot infer". Run 1 cannot support that conclusion, because
it cannot distinguish "the knowledge base adds nothing" from "these cases are too easy to tell".
Both remain live.

