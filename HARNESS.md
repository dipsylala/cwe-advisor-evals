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
small fixed subset when a fresh estimate of the sample floor is needed. The reuse key for a frozen
sample is everything that produced it: the corpus commit and fixture contents, the arm model, the
arm prompt, and the execution settings - not the corpus version alone. Any of those changing means
a fresh A. Recorded exceptions, all compile-only edits made after run 16 when the type check
(Step 0) first ran, none touching a sink, a call chain or a finding: `79/java/ThymeleafUtextUnescaped`
lost the `public` modifier on its controller class (a public class must sit in a file of its own
name); `22/csharp/PathCombineAbsoluteOverride` and `22/csharp/PathCombineUnsanitizedFilename`
qualify `File.ReadAllText` as `System.IO.File` (inside a `ControllerBase`, bare `File` binds to
the `File(...)` action-result method and does not compile); `94/csharp/CSharpCompilationRuntimeCompile`
gained `using Microsoft.CodeAnalysis.Emit` for `EmitResult`; `90/csharp/LdapSearchFilterConcat`'s
anonymous response type names its two indexer members (`displayName`, `mail`), which C# requires;
`352/csharp/MvcControllerIgnoreAntiforgeryToken` and `862/csharp/MinimalApiMissingAuthorizeMetadata`
gained the `using` for the namespace their sibling file declares. The frozen samples for those
seven cases were produced against the pre-edit files.

**A runner or judge that has already read the knowledge base cannot credibly produce arm A.** Run
each arm and each judge as a separate agent with its own context.

**Pin an explicit model for every arm and judge agent, and record it in the run's `RESULTS*.md`.**
An `agent()` or Agent-tool call that omits a model override inherits whatever model is running the
orchestrating session - which changes across sessions and is easy to lose track of. Runs 1-6 did
this; all of them ran under whatever model powered the session at the time (Sonnet 5 for runs 5 and
6), undocumented and unpinned. Every comparison in this harness so far is "one model with guidance
vs. the same model without" - none of it has been repeated on a second model, so a benefit or defect
found here has not been shown to generalise across models.

## Step 0 - check the fixtures parse

```sh
python evals/scripts/parsecheck.py
```

Every case fixture must parse with the language's own tool (`php -l`, `node --check`, `py_compile`,
`gofmt -e`, `perl -c`, `javac` and `dotnet build` with resolution errors filtered out; C and C++
need a compiler, which CI has and the authoring machine does not). A fixture that does not parse as
shipped cannot be judged by building a fix against it, and any compile gate on arm output needs
this as its floor. The fixtures carry no dependency manifests, so this is a parse check, not a
type check: an invented method or package in a fixture would pass it. Templates hosted by a
framework (`.jsp`, `.razor`, `.cshtml`) are reported as unchecked. The same sweep runs on every
push to `cases/` in the evals repo's CI, and `git config core.hooksPath .githooks` in `evals/`
runs it on the cases in each commit.

The type check sits on top of it:

```sh
python evals/scripts/compilecheck.py
```

The third-party surface of each language across the whole corpus is a short list - about twenty
Maven artifacts for 86 Java cases, thirteen NuGet packages for 54 C# cases, twenty npm packages,
five Go modules, twenty PyPI packages - so one superset manifest per language under `stubs/`
resolves every case without per-case manifests: a pom resolved once into a classpath, a `.csproj`
restored once, a `package.json` installed once, a `go.mod`, a `requirements.txt` in an isolated uv
environment. Classes and modules a fixture references but does not ship (a repository, an entity,
a config module, Juliet's `testcasesupport`, the Benchmark helpers) are compile-only stand-ins
under `stubs/<language>/`. Every case resolves: Java 85, C# 51, JavaScript 47, Go 43, Python 52,
PHP 44, C 22, C++ 19; the rest are unchecked because they cannot exist outside their host (two
ASP.NET Web Forms pages, a JSP, a Blazor component) or because a native binding will not build
here (`libxmljs`). Seven fixtures needed compile-only edits to get there, recorded under **What a
run is**. C and C++ use `gcc`/`clang -fsyntax-only` where present and otherwise MSVC's `cl /Zs`
through the Visual Studio developer script, with `stubs/c/msvc_compat.h` force-included for the
POSIX spellings MSVC lacks (`ssize_t`); both are the compiler's full semantic pass. PHP is PHPStan
at level 2 (unknown classes, functions, methods, properties) with Larastan for the Laravel facades
and Eloquent models, booted through Orchestra Testbench from a composer superset in `stubs/php`;
one fixture carries a per-case ignore (`phpstan-ignore.txt`) because the error PHPStan reports,
the `/e` regex modifier, is the CWE-94 sink the case exists to test. Perl has the parse check
only.

What the type check catches is the run-13 to run-16 slip bucket applied to the fixtures - an
invented method, a missing `using`, a package that does not exist - and it is the floor for
applying the same check to a fix, which needs the write-up to carry complete files.

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

Create the output tree first with `python evals/scripts/collect.py mkdirs evals/runs-v4/A` (and `B`),
so no agent has to create a directory - from run 13 on, agents asked to create the parent of
their output path produced dozens of `<id>/<id>.md` nestings and empty `<id>/` directories.

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

Then collect and validate each arm mechanically:

```sh
python evals/scripts/collect.py arm evals/runs-v4/A --out /tmp/done-A.json
```

It flattens any `<id>/<id>.md`, removes empty directories and stray scratch files, checks the
required headings, compares the set of write-ups against the corpus, and writes the done-set the
arm workflow takes as `args` to run only what is missing. Never trust a workflow's own success
tally - count the files.

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

Two shapes recur often enough to pin. A fix that adds a restriction the original did not have - an
allowlist, a length or character bound, a newly required parameter, an authorization check on a
path that was open - and that could reject an input the contract or the original code accepted,
scores 1 even when the write-up states it, unless the stated contract calls for that restriction.
Extra hardening against a different weakness - a cookie flag, a header, a stricter default - that
blocks no legitimate use and is stated scores 2.

(That paragraph was added after run 16, where a sample of the no_harm splits showed about half
were this gray zone rather than disagreement about facts. Re-judging run 16's worst segment under
it, 19 write-ups, took no_harm splits from 7 to 3 with the mean unchanged within 0.1; on 19 items
that is directional, not proof, and run 17's frozen sets carry the real measurement.)

Write one JSON object keyed by run id to {scores-dir}/judge{N}.json:
{"R101": {"fix_quality": 2, "no_harm": 2, "note": "..."}, ...}

All {n} must be present. Reply with just the path and the count.
```

Add `source_identified` and `verdict_correct` to the rubric only if the run includes cases whose
exploitability the arm must determine. Under the current true-positive scope it is given.

### Bundled judging (from run 16)

Measured on run 16's judges under the prompt above, the median judge agent took 31 turns and
re-sent about 120k tokens of context on each of them (3.7M input tokens per judge, most of it
cache reads), spent a third of its tool calls discovering and reading case files, and called
WebSearch three times. Validated on run 15's segment s3 against its own three-judge panel, judges
given a prepared bundle instead agreed with the original scores on 35 of 40 `fix_quality` and 33
of 40 `no_harm` means, were slightly stricter (-0.12 / -0.16), took 7-19 turns, and caught two
compile errors the original panel had passed (an invented `com.googlecode.owasp...` package where
the jar has `org.owasp.html`; two interpolated strings concatenated into a plain `string` where
`ExecuteSqlInterpolatedAsync` needs a `FormattableString`) - both reproduced before being believed.
The same bundles judged by the restricted `cwe-judge` agent type (below) agreed on 33 and 30 of 40,
split among themselves on 1 and 2 write-ups against the original panel's 4 and 6, started each
turn from 17.8k tokens of context instead of 45k, and spent more turns compiling (9-28, mostly
Bash). Per write-up that is roughly 62k input tokens against the old protocol's 92k - a smaller
saving than the turn count suggests, because the judges now verify by building - with a stricter
and more consistent panel. From run 16 the protocol is:

```sh
python evals/scripts/bundle.py /tmp/blind-v4 --out /tmp/bundle-v4 --max-bytes 80000
```

Each `s<idx>.md` holds every blinded write-up in that segment followed by the complete contents of
its case directory, minus `case.json` and anything that is not source; segments are packed by
size so each fits one Read. `index.json` records which run ids are in which segment. The judge
prompt is the one above with the "Write-ups:" and "Do NOT read:" lines replaced by

```text
Everything you need is in one bundle file: {bundle-dir}/s{idx}.md
Read it in full (use offset and limit if a single Read does not return all of it). It contains
each write-up followed by the complete contents of its case directory. Do not read anything else
on disk and do not search the web; if a specific claim can only be settled by compiling or
running something, you may do that with Bash in a scratch directory outside the repository and
say so in the note.
```

Dispatch judges as the `cwe-judge` agent type (`.claude/agents/cwe-judge.md`: Read, Write and Bash
only, so the judge carries no web search or MCP tool surface), and validate with

```sh
python evals/scripts/collect.py judges /tmp/scores-v4 --index /tmp/bundle-v4/index.json
```

which prints the done-set of valid `s<idx>-<j>` keys for a relaunch. The rubric, the three
judges per write-up, and the one-pool blinding are unchanged; only what the judge is handed and
what it can reach changed.

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
- **The session limit kills a workflow mid-run, and its tally undercounts the disk.** Runs 13, 14
  and 15 all lost arm or judge agents to the session limit (79 of 84 judges in one launch). The
  outputs already written are fine; the workflow's own success count is not - it reported 5 where
  10 valid judge files were on disk, and 13 where 14 arm outputs were. Recover by validating what
  is on disk (every judge file parses and carries exactly its segment's run ids; every arm output is
  a flat `<cwe>/<lang>/<id>.md`), passing the valid keys to the script as a done-set through `args`,
  and relaunching - the script skips those and runs the rest under the identical prompt. Never
  trust the tally; count the files.
- **Agents inherit the launcher's working directory.** The Bash tool's `cd` persists across calls,
  and Workflow agents start in whatever directory it was left in. Run 15's first arm launch went out
  with `evals/` as the working directory, so every repo-root-relative path in the prompt pointed at
  nothing and no output was written. `cd` to the repository root immediately before launching, and
  tell manifest and judge agents the absolute root to `cd` to first.
- **Arm agents nest or duplicate their output.** Some write `<id>/<id>.md` instead of `<id>.md`,
  some leave an empty `<id>/` directory after a `mkdir -p` on the file path, and one wrote a
  byte-identical copy to a mangled `E:Github...` path. `scripts/blind.py` reads one level only, so
  flatten (move `<id>/<id>.md` up, delete empty directories) and recount before blinding; the
  count must equal the case count exactly.
