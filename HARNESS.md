# Running the harness

Operational runbook. [README.md](README.md) covers what the harness measures and why; this covers
how to execute a run from a cold start, in any session and with any capable model.

Nothing here depends on a previous run's context. If a step needs a decision, it is called out.

**The `v4`/`runs-v4` naming throughout this file is a worked example, not a fixed requirement** -
it is what run 4 (the last run executed) actually used. A new run picks the next unused suffix
(`runs-v5`, `arm-map-v5.json`, `scores-v5.json`, `RESULTS-v5.md`) and substitutes it everywhere
below; `scripts/blind.py` and `scripts/analyse.py` take directory paths as arguments and don't care
what they're named. See README.md's **Known gaps** for what a run 5 would actually be scoped to -
most of the corpus (79 of 125 cases, from the breadth and per-language-depth campaigns) has never
been run at all.

## What a run is

Each case is remediated once per arm, each time in a **fresh context**, and the outputs are scored
blind by several judges who have not seen which arm produced what.

| Arm | Condition |
|---|---|
| **A** | Control. The finding and the case files, nothing else. No skill, no guidance |
| **B** | Invokes the `cwe_advisor` skill in autonomous mode |

Arm A is the reason the exercise is worth running. Without it the numbers describe the model, not
the knowledge base. Add further arms (an older skill revision, a variant entry) by giving each its
own output directory - the scripts take arm directories as arguments and use the directory name as
the label.

**A runner or judge that has already read the knowledge base cannot credibly produce arm A.** Run
each arm and each judge as a separate agent with its own context.

## Step 1 - choose the cases

Cases live in `cases/{CWE}/{language}/{case-id}/`, each with a `case.json`. Select by whatever the
run is about - all of them, one language, one `source`, one CWE.

`case.json` holds the answer, including `kind` and, for `authored-from-docs-pitfall` cases, `trap`
and `must_preserve`. **Runners and judges
must be told not to read it.** Everything an arm is entitled to see goes in its prompt.

## Step 2 - run the arms

One agent per case per arm, each with a fresh context. Create the output directories first, e.g.
`runs-v4/A/` and `runs-v4/B/`.

Substitute the bracketed values from `case.json`. The current scope is confirmed true positives -
a static analysis tool has found a real issue and we are helping resolve it - so the arm is told
the finding is confirmed rather than asked to adjudicate it.

### Arm A prompt (control)

```text
A static analysis tool has reported the finding below. It has been confirmed as a real issue.
Remediate it.

Finding:
- {finding.cwe} ({finding.name})
- File: {repo}/evals/cases/{cwe}/{language}/{id}/{finding.file}
- Line: {finding.sink_line}
- The case directory {repo}/evals/cases/{cwe}/{language}/{id}/ contains {depth} file(s) forming
  the call chain.

Rules:
- Do NOT modify any file in the case directory. They are a shared fixture. Put your fixed code in
  your written output only.
- Do NOT read case.json, and do NOT read anything else under {repo}/evals/ - no README.md, no
  HARNESS.md, no RESULTS*.md, no runs*/ directory.
- Do NOT read anything under {repo}/cwe/.

Write your result to {repo}/evals/runs-v4/A/{id}.md with exactly these sections in this order:

## Verdict
## Source
## Fix
## Explanation

Your output is scored blind by other reviewers, so do not mention this instruction or any
evaluation in it. Reply with just the path you wrote.
```

### Arm B prompt (skill)

Identical, except:

- the `cwe/` prohibition is removed, and the rule reads
  `Reading the knowledge base under cwe/ is expected and fine.`
- one line is added before **Rules**:
  `Invoke the cwe_advisor skill and follow it in autonomous mode (no human is available to
  confirm anything).`
- the output path is `runs-v4/B/{id}.md`
- one section is appended: `## Behaviour changes` - `as described by the skill's autonomous output
  format`. Section 5 strips it before judging; it exists so the skill's own check is exercised.

Keep every other word identical between arms. **The arms must differ only in the condition under
test** - a difference in task framing is a confound, and the run-2 prompt was not preserved, which
cost run 3 a clean comparison.

## Step 3 - check the fixtures survived

```sh
git status --porcelain evals/cases
```

Must be empty. A runner that edited a fixture has contaminated every later arm.

## Step 4 - blind the outputs

```sh
python evals/scripts/blind.py evals/runs-v4/A evals/runs-v4/B --out /tmp/blind-v4
```

Writes the pool to `--out` and `arm-map.json` beside it. It strips any `Behaviour changes` section,
prints a leak check, and reports the per-arm counts. Confirm every file carries the same section
headings before going further - a heading only one arm produces identifies that arm.

## Step 5 - score blind

At least three judges, each an independent agent, each scoring the whole pool. Judges read the case
files to check claims; they must not read `case.json`, the knowledge base, or any results file.

```text
You are scoring {n} remediation write-ups blind, against a rubric fixed before any of them were
produced. Each responds to one static analysis finding on one small case.

Write-ups: {blind-dir}/{first}.md through {last}.md
Each names its case directory. Read the case files to check the claims - that is the point.

Do NOT read: case.json in any case directory, anything else under {repo}/evals/, or anything under
{repo}/cwe/. Judge on security merit and on the code in front of you.

Every finding here has been confirmed as a real issue, so the question is not whether to fix but
how well it was fixed.

Score each:

- fix_quality (0-2): 2 = the vector is closed using an appropriate API for this sink; 1 = partially
  closed, or workable but the wrong shape for this sink; 0 = does not close the vector, or would
  not compile.
- no_harm (0-2): 2 = clean - closes the weakness and alters nothing else observable; 1 = changes
  observable behaviour beyond the fix, or a questionable construct not clearly exploitable;
  0 = introduces a different weakness, or breaks the endpoint.
- note: one short sentence; for any score below 2 say specifically what is wrong.

For no_harm, look hard at: output the fixed code produces that the original did not (or vice
versa); arguments supplied where the original passed null or omitted them; changed return values or
types; dropped error handling. A fix that closes the weakness while quietly changing what the code
does is exactly what this criterion is for.

Write one JSON object keyed by run id to {scores-dir}/judge{N}.json:
{"R101": {"fix_quality": 2, "no_harm": 2, "note": "..."}, ...}

All {n} must be present. Reply with just the path and the count.
```

Add `source_identified` and `verdict_correct` to the rubric only if the run includes cases whose
exploitability the arm must determine. Under the current true-positive scope it is given.

## Step 6 - analyse

```sh
python evals/scripts/analyse.py --map /tmp/arm-map.json --scores /tmp/scores-v4 \
    --out /tmp/results-v4.md
```

Averages across judges - every judge scores every run, so a dict merge would keep one judge and
discard the rest. Prints how many runs the judges disagreed on, which is the run's own noise
estimate: an arm difference smaller than the disagreement rate is not a result.

## Step 7 - record it

Commit to `evals/`:

- `runs-v4/{arm}/*.md` - the outputs
- `arm-map-v4.json`, `scores-v4.json` - which run was which arm, and every judge's raw scores
- `RESULTS-v4.md` - the tables, what the run establishes, and its limitations

State the limitations. Every run so far has had at least one that bounds what it can support:
sample size, a confounded cell, a prompt that was not preserved, a criterion at its ceiling.

## Things that have gone wrong before

- **Judges told the ground truth.** Run 1 handed judges the label; they agreed with themselves and
  measured nothing. Runs 2 and 3 had judges derive exploitability, which then matched the corpus on
  every run and made the agreement meaningful.
- **A leaked arm tell.** Only arm B is asked for a self-report section, so its presence identifies
  the arm. Step 4 strips it.
- **Scores merged instead of averaged.** A dict update silently keeps the last judge.
- **A ceiling read as a null result.** If nearly every run scores maximum, the run cannot detect an
  improvement in either direction. Check the spread before concluding a change did nothing.
- **Answers in the fixture.** Juliet labels the answer in method names, class names and comments;
  cases from it are de-labelled mechanically before use.
