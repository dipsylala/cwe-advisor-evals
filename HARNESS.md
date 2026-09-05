# Running the harness

Operational runbook. [README.md](README.md) covers what the harness measures and why; this covers
how to execute a run from a cold start, in any session and with any capable model.

Nothing here depends on a previous run's context. If a step needs a decision, it is called out.

**The `v4`/`runs-v4` naming throughout this file is a worked example, not a fixed requirement** -
it is what run 4 used when this file was first written. A new run picks the next unused suffix -
check `evals/` for the highest existing `runs-v*`/`RESULTS-v*.md` and increment it - and substitutes
it everywhere below; `scripts/blind.py` and `scripts/analyse.py` take directory paths as arguments
and don't care what they're named. See README.md's **Known gaps** for what remains unscored, and
**Past runs** for what the highest-numbered run so far actually used.

## What a run is

Each case is remediated once per arm, each time in a **fresh context**, and the outputs are scored
blind by several judges who have not seen which arm produced what. The normal top-15 scope assumes
the scanner is upstream of this harness: the finding has already been confirmed as a true positive,
and the run measures the quality of the fix, not whether the model can rediscover the bug.

| Arm | Condition |
| --- | --- |
| **A** | Control. The finding and the case files, nothing else. No skill, no guidance |
| **B** | Invokes the `cwe_advisor` skill in autonomous mode |

Arm A is the reason the exercise is worth running. Without it the numbers describe the model, not
the knowledge base. Add further arms (an older skill revision, a variant entry) by giving each its
own output directory - the scripts take arm directories as arguments and use the directory name as
the label.

**From run 15 the control is a frozen sample, not a fresh one.** Arm A never reads `cwe/`, so an
entry or SKILL.md edit cannot move it; re-running it only re-samples the model (run 11 -> 13 moved
it -0.03 / -0.05 on 372 cases with nothing changed, and -0.10 / -0.23 on a 14-case subset). Keep one
arm-A sample per corpus version - `runs-v15/A` is run 13's outputs with the 14 cases in the slots
re-edited after it taken from run 14 - and copy it into every later run's pool so the same judge
panel scores it beside the fresh B set. Panels drift too, so carry A's text forward, never its
scores: A's movement between runs is then the panel's, and B's movement beyond it is the change
under test. Copying the previous B set's text in as well (`B-pre`) measures the edit directly under
identical judging for the cost of judge agents only. Re-sample A when the corpus changes, or on a
small fixed subset when a fresh estimate of the sample floor is needed.

**A runner or judge that has already read the knowledge base cannot credibly produce arm A.** Run
each arm and each judge as a separate agent with its own context.

**Pin an explicit model for every arm and judge agent, and record it in the run's `RESULTS*.md`.**
An `agent()` or Agent-tool call that omits a model override inherits whatever model is running the
orchestrating session - which changes across sessions and is easy to lose track of. Runs 1-6 did
this; all of them ran under whatever model powered the session at the time (Sonnet 5 for runs 5 and
6), undocumented and unpinned. Every comparison in this harness so far is "one model with guidance
vs. the same model without" - none of it has been repeated on a second model, so a benefit or defect
found here has not been shown to generalise across models.

## Step 1 - choose the cases

Cases live in `cases/{CWE}/{language}/{case-id}/`, each with a `case.json`. Select by whatever the
run is about - all of them, one language, one `source`, one CWE.

`case.json` holds the answer, including `kind` and, for `authored-from-docs-pitfall` and
`authored-top15-fix-complexity` cases, `trap` and `must_preserve`. **Runners and judges must be told
not to read it.** Everything an arm is entitled to see goes in its prompt.

## Step 2 - run the arms

One agent per case per arm, each with a fresh context. Create the output directories first, e.g.
`runs-v4/A/` and `runs-v4/B/`. If orchestrating with the Workflow tool, pass an explicit `model` in
each `agent()` call's options rather than omitting it - see the model note above.

Substitute the bracketed values from `case.json`. The current scope is confirmed true positives -
a static analysis tool has found a real issue and we are helping resolve it - so the arm is told
the finding is confirmed rather than asked to adjudicate it. Do not add prompt language asking the
arm to verify whether the scanner is right unless the run is explicitly about false positives.

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

Where a case states a `must_preserve` contract, the blinded file's header carries it as a
`Contract to preserve:` line (from run 12 on), so judges score `no_harm` against the stated contract
rather than each inventing their own. `trap` and `origin` are never copied through - they name the
intended wrong fix and would tell a judge what to look for.

## Step 5 - score blind

At least three judges, each an independent agent, each scoring the whole pool. Judges read the case
files to check claims; they must not read `case.json`, the knowledge base, or any results file. Pin
an explicit model here too - see the model note under **What a run is**. Judges do not need to run
the same model as the arms, but whichever model they run should be recorded.

```text
You are scoring {n} remediation write-ups blind, against a rubric fixed before any of them were
produced. Each responds to one static analysis finding on one small case.

Write-ups: {blind-dir}/{first}.md through {last}.md
Each names its case directory. Read the case files to check whether the proposed fix actually closes
the reported sink and preserves behavior - that is the point.

Do NOT read: case.json in any case directory, anything else under {repo}/evals/, or anything under
{repo}/cwe/. Judge on security merit and on the code in front of you.

Every finding here has been confirmed as a real issue, so the question is not whether to fix but
how well it was fixed.

Where a write-up's header carries a "Contract to preserve:" line, that is the sink's stated
contract - score no_harm against it, not against your own reading of what the original preserved.
Where there is no such line, derive the contract from the case files as usual.

Score each:

- fix_quality (0-2): 2 = the vector is closed using an appropriate API for this sink; 1 = partially
  closed, or workable but the wrong shape for this sink; 0 = does not close the vector, or would
  not compile.
- no_harm (0-2): 2 = clean - closes the weakness and alters nothing else observable, or the only
  other change is stated plainly in the write-up and does not stop a legitimate caller from
  succeeding; 1 = changes observable behaviour beyond the fix, or a questionable construct not
  clearly exploitable, or the fix stops legitimate use but the write-up states that openly as a
  known, required follow-up; 0 = introduces a different weakness, or silently stops the endpoint
  working for legitimate use without saying so.
- note: one short sentence; for any score below 2 say specifically what is wrong.

For no_harm, look hard at: output the fixed code produces that the original did not (or vice
versa); arguments supplied where the original passed null or omitted them; changed return values or
types; dropped error handling. A fix that closes the weakness while quietly changing what the code
does is exactly what this criterion is for - "quietly" is load-bearing: the same change stated
plainly in the write-up is a lesser defect than the identical change left for the reader to find,
because a reviewer or an automated gate reading the write-up can catch a stated change before the
fix ships and cannot catch a silent one. Disclosure does not launder a change that stops legitimate
use into a 2 - it moves a 0 to a 1, not a 0 to a 2.

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
- **A judge's "reproduced" was wrong.** Testing the no_harm rubric wording added after run 6, a
  fresh panel re-judging the same six run-6 write-ups reversed the original panel's read of
  `DeprecatedEntityLoaderGuard` (CWE-611/php) - unanimously, and citing "matches repro" - concluding
  external entity resolution is dead on PHP 8.2+ regardless of `LIBXML_NOENT`. A direct reproduction
  (PHP 8.5.8/libxml 2.11.9) showed the opposite: `LIBXML_NOENT` does re-enable external `SYSTEM`
  entity resolution and leaks file contents; without it, the same entity resolves to empty. The
  likely cause is mundane and worth naming - a naive `file://$path` URI on Windows mixes backslashes
  into the path and produces `Invalid URI`, which reads as "the entity didn't resolve" instead of
  "the test URI was malformed," and this session hit the identical bug on its first attempt. A
  judge's self-reported reproduction is not independently verified; treat a claim as unconfirmed
  until it is reproduced outside the judge's own transcript, especially before editing an entry
  because of it.
