# Validation harness

Validates the knowledge base in [dipsylala/cwe-advisor](https://github.com/dipsylala/cwe-advisor) -
this repo is linked into it as a git submodule at `evals/`. Every path below (`cwe/{CWE}/...`, the
`{repo}` placeholders in HARNESS.md) refers to that parent checkout, so run the harness from inside
a `cwe-advisor` clone with this submodule initialized (`git submodule update --init`), not from a
standalone clone of this repo.

## What this measures

CWE guidance in the parent repo is written and reviewed on reasoning alone - nothing is measured by
default. This harness exists to put numbers against three durable questions:

1. **Does the knowledge base improve remediation after a scanner has already found a real issue?**
   The current top-15 corpus assumes a SAST, LLM, or hybrid scanner has reported a confirmed true
   positive. The arm is not being asked to rediscover or adjudicate the bug; it is being asked to
   fix the reported sink correctly.
2. **Does review effort show up in output quality?** Tested by splitting cases between CWEs a
   review pass covered and CWEs it never touched.
3. **Does a specific content or workflow change show up in fix quality?** Tested with before/after
   comparisons on the same entries or the same SKILL.md logic.

Run 17 is the current measurement: on 372 cases across 27 CWEs and nine languages, with every
fix compile-gated, guidance lifts `fix_quality` on Haiku 4.5 from 1.80 to 1.91 (ahead on 64
cases, behind on 22) and leaves `no_harm` (whether a fix silently breaks or changes something the
sink's caller depended on) level, 1.76 against 1.74. See **Runs** below and
[RESULTS-v17.md](RESULTS-v17.md). Earlier runs were removed at the run-17 boundary; **Known
gaps** below says what remains unverified rather than just measured.

## Corpus

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

Current contents: 372 cases across 27 CWEs and nine languages (perl added by the CWE-79 depth
batch below; c and cpp added by the top-15 fix-complexity batch). Five sources:

| `source` | n | What it is |
|---|---|---|
| `owasp-benchmark` | 16 | Single-file Java servlets, labels from `expectedresults-1.2.csv` |
| `juliet` | 17 | Java multi-file flow variants, de-labelled mechanically; taint crosses 2, 4 or 5 files |
| `authored-from-docs-pitfall` | 13 | Single-function cases across Java, Python, Go, C#, JavaScript and PHP, each built around a fix that looks right and is not |
| `authored-top15-fix-complexity` | 85 | True-positive remediation cases for 2025 CWE Top 15 entries with explicit `trap`, `must_preserve`, and `origin` metadata; several cross files, and all test fix shape rather than finding adjudication |
| `authored` | 102 | Plain true-positive cases with no `trap`/`must_preserve`/`origin` - language-coverage, top-15 depth, or (11 cases, see below) multi-file chains crossing 2-5 files, not a discrimination instrument |

**`owasp-benchmark` and `juliet`** are externally authored, so their ground truth doesn't come from
this repo: Benchmark ships `expectedresults-1.2.csv`, Juliet encodes it in the variant name (then
mechanically stripped before use). A case written here would be shaped toward the guidance -
unconsciously matching the vulnerability to the form the entry already describes - which manufactures
whatever result was wanted. That is why these two are weighted as the stronger ground truth.

**`authored-from-docs-pitfall`** cases exist because the first runs measured the first two sources to
saturation - chain depth never discriminated, every recorded harm was sink-local. These drop the
chain and instead vary how much contract the sink has and how wrong a plausible fix is. Each is built
from a `Common Pitfalls` bullet in the `docs/` corpus (actor/critic reviewed across two model
families) and carries three extra fields, since the intended difficulty needs to be explicit and
checkable rather than implied by the code:

- **`trap`** - the plausible fix that does not close the finding, or closes it while breaking
  something.
- **`must_preserve`** - the sink's contract a correct fix has to keep. This is what `no_harm` should
  be scored against, though the judge prompt in HARNESS.md does not yet pass it through - see
  **Known gaps** below.
- **`origin`** - the `docs/` pitfall the case is built from.

Their labels are an authoring claim, not an external ground truth, which is weaker than the other
two sources. Treat a judge disagreeing with `kind` on one of these as a finding about the case.
Run 17's by-source table in [RESULTS-v17.md](RESULTS-v17.md) shows what they catch now.

**`authored-top15-fix-complexity`** cases cover the 2025 CWE Top 15 entries with remediation-quality
pressure rather than detection labels. The scanner finding is part of the prompt and is treated as
confirmed. The case succeeds only if the produced fix closes that true positive while preserving the
observable contract, and each carries the same `trap`/`must_preserve`/`origin` fields as the pitfall
cases above. Built up over many authoring passes tracked in `git log` (this directory's own commit
history names what each pass added and why); see **2025 Top 15 Fix-Quality Target** below for the
current state and `cases/{cwe}/{language}/` on disk for the cases themselves.

### 2025 Top 15 Fix-Quality Target

The 2025 CWE Top 15 (CWE-79, 89, 352, 862, 787, 22, 416, 125, 78, 94, 120, 434, 476, 121, 502, per
MITRE's 2025 Top 25 list) is the priority set for remediation-quality pressure. The target is not
equal volume everywhere: a common, already-easy sink does not need another direct case. A top-15
CWE counts as "hammered" only when it has ordinary true positives, at least one multi-file or
cross-layer flow where that shape is natural, and at least one explicit wrong-fix/contract-
preservation case. These are not scanner-benchmark cases: the finding is already known, so added
detail should make the fix decision harder, not make the bug harder to notice.

CWE-120 has no dedicated fixture: `cwe/120/INDEX.md` routes a finding to CWE-121 (stack
destination) or CWE-787 (every other destination) rather than duplicating either entry's
remediation, the same pattern `cwe/77` already uses for `cwe/78`. Per-CWE case counts and traps are
`cases/{cwe}/{language}/` on disk.

For future top-15 batches, prefer cases that combine two axes from this list: multi-file flow,
existing partial mitigation, plausible wrong fix, and observable contract preservation. Single-file
cases are still useful for native memory and API-specific pitfalls, but a new one should name the
fix mistake it is designed to catch, and should target a genuinely distinct datapath rather than
padding an already-hammered CWE.

**`authored`** cases come from two related but distinct campaigns, both tracked in
[TODO.md](TODO.md), neither built around a deliberate wrong-fix:

- **Per-language coverage (breadth).** At least one case per `(CWE, language)` slot that has a
  language-specific entry. CWE-22, 78, 89, 90, 117, 209, 326, 330, 338, 347, 434, 502, 611 and 614
  are fully covered across every language their entry has.
- **Top-15 depth.** For the CWEs this project's own MITRE Top-25 ranks-1-15 review covered
  (CWE-20, 22, 77, 78, 79, 89, 94, 125, 269, 287, 352, 416, 434, 787, 862 - 20 and 269 are
  root-only and out of scope), a target of 3 cases per `(CWE, language)` slot rather than 1, each
  built from a distinct named pattern in that language's `docs/CWE-{ID}/{language}/index.md`
  "Common Vulnerable Patterns" section (adapted into an original scenario, not copied verbatim).
  CWE-79 was the first one done: all 7 of its languages (including the newly-added perl) have 3
  cases each. CWE-77 is the second: csharp/java/php/python (its only 4 languages) now have 3 cases
  each too, scoped strictly to the non-shell interpreters this entry covers (Redis/Memcached inline
  protocol, raw-socket SMTP/IMAP/FTP, PHP dynamic dispatch) - never a CWE-78 shell pattern, which
  would misfile the case. Remaining, in MITRE rank order: 78, 89 (both already breadth-complete at
  1/language, need 2 more per slot), 94, 125, 287, 352, 416, 434 (same), 787, 862.
- **Multi-file depth.** Every `authored` case above is single-file (`depth: 1`) - the only multi-file
  cases in the corpus were `juliet`'s, and only in Java. 11 new cases (one per language slot across
  CWE-79 and CWE-77, `depth` 2-5) test whether tracing across files - which the first runs found saturated
  on Sonnet 5 up to 5 files, only ever on Juliet's Java cases - holds on other languages and other
  models. Each threads untrusted input through genuine intermediate logic (a value object, a
  service layer, a partial allowlist that checks one half of a value but not the other) rather than
  a bare pass-through, so the chain has to be traced, not just walked past boilerplate.

Every case, regardless of source, is written by a workflow agent that reads the target entry's own
`Taint Sinks` list (and, for the depth campaign, the named `docs/` pattern) and has its
`sink_line`/`sink_code` checked against the file it actually wrote before being accepted.

### Adding a case

Create `cases/{CWE}/{language}/{case-id}/` with the source files and a `case.json`:

| Field | Meaning |
|---|---|
| `id` | Directory name. Stable once a run has referenced it |
| `cwe`, `language` | Match the directory position |
| `source` | Where the case came from, for judging independence from the guidance |
| `kind` | `true_positive` or `false_positive` |
| `depth` | Files in the call chain from source to sink |
| `group` | `reviewed` or `unreviewed`, for the review-effort split (the CWEs the top-15 review covered are `reviewed`; everything else is `unreviewed` - a split designed for the first run, whose records are in git history) |
| `files` | Source files, in call order |
| `finding` | What the scanner reports and the arm is told to fix: `cwe`, `name`, `file`, `sink_line`, `sink_code`, `summary` |
| `trap`, `must_preserve`, `origin` | `authored-from-docs-pitfall` and `authored-top15-fix-complexity` only. A plain `authored` case omits all three |

`case.json` holds the answer, so **runners and judges must be told not to read it**, the same way
they are told not to read `RESULTS*.md` or the `runs*/` directories. Everything an arm is entitled
to see is handed to it in the prompt: the case directory, the CWE, and the sink file and line.

Two properties matter more than volume. **Cases must be externally authored or independently
derived** - a case written against the guidance takes the shape the guidance already describes and
manufactures whatever result was wanted. And **ground truth must come from outside the case**: a
label that is only an assertion in its own metadata cannot settle a disagreement with a judge.

## Running a test

Full runbook, with the arm and judge prompts verbatim: [HARNESS.md](HARNESS.md). In short: each case
is remediated once per arm (arm A = no guidance, arm B = the skill invoked in autonomous mode),
each arm run as a **fresh context** that has not read the knowledge base, then all outputs are
blinded (`scripts/blind.py`) and scored by at least three independent judges who have not seen which
arm produced what, and finally aggregated (`scripts/analyse.py`) into comparison tables.

Both scripts are generic - they take arm directories as arguments and use the directory name as the
label, so nothing needs editing to add an arm or start a new run. Pick the next unused version
suffix (`runs-v18`, `scores-v18`, `arm-map-v18.json`, `RESULTS-v18.md`); HARNESS.md's `v4` examples
are a worked example, not a fixed name.

### Known gaps

- **`no_harm` is scored against the stated contract where a case has one.** `scripts/blind.py`
  copies `must_preserve` into the blinded header as `Contract to preserve:` - never `trap` or
  `origin`, which would reveal the intended wrong fix. The 274 cases without a contract are scored
  against the judges' own reading of what the original preserved, and that is where judges split
  most: 51 of 372 unguided and 64 of 372 guided write-ups in run 17 had a `no_harm` split, about
  half of them the disclosed-narrowing gray zone the rubric pin was added for.
- **The rubric and the entries disagree on allowlists.** The pin scores an added allowlist as
  narrowing unless the contract calls for it; the CWE-77, 78 and 90 entries prescribe allowlists
  beside the API fix. Ten of the guided arm's unanimous `no_harm` misses in run 17 are that shape.
  Open - see HARNESS.md Step 5.
- **A judge's self-reported "reproduced" is not independently verified.** A fresh panel once
  unanimously reversed a correct technical read while citing its own reproduction; direct
  reproduction showed the original panel right. Treat a judge's reproduction claim as provisional
  before it changes an entry - see HARNESS.md's **Things that have gone wrong before**.
- **Fixes are built, not executed.** Fixtures parse and type-check (`scripts/parsecheck.py`,
  `scripts/compilecheck.py`, in CI and the pre-commit hook) and `scripts/fixgate.py` builds every
  fix against its fixture, which catches the invented-name and missing-import bucket at no token
  cost (16 of 372 unguided and 18 of 372 guided in run 17). Nothing runs a fix: one that builds
  and does the wrong thing, or closes the sink and breaks the contract, is still the judges' to
  see. Nine fixtures are unchecked (Web Forms, JSP, Blazor, JSX, a native binding), and the gate
  reflects one dependency environment per language.
- **One model.** The current corpus and format have been measured on Haiku 4.5 only. Sonnet 5
  saturated `fix_quality` on earlier corpora (records in git history before the run-17 boundary),
  so it cannot show a guidance effect on that axis; its `no_harm` under the current judging is
  unmeasured. A Sonnet run needs its own frozen unguided sample.

## Runs

Run 17 is the current baseline and the frozen unguided control for later runs; run 18 is the first targeted run on top of it. Runs 1-16 - the
records, scores and results files - were removed at the run-17 format boundary, because the
current corpus, judging and write-up format no longer share a scale with them; they remain in this
repository's git history before that commit, and HARNESS.md keeps the lessons they taught.

| Run | Corpus | Runs | Question | Headline | Results |
|---|---|---|---|---|---|
| 17 | Same 372 cases; a format boundary - write-ups carry the complete changed files - with fresh unguided (A) and guided (B) Haiku 4.5 samples, no B-pre, and `scripts/fixgate.py` building every fix against its fixture | 744 (372 x 2 sets) | Does the guided fix build, and what does a compile gate find that sixteen judged runs did not? | Gate: 16 of 372 unguided and 18 of 372 guided fixes do not compile (one checker false positive excluded) - the same 4-5% either way, in different shapes: A invents helper methods and leaves Go variables unused, B mis-imports or mis-packages the library the entry names. Four B failures traced to two entries naming a class without its package (`JexlSandbox`, `Encode`), both fixed - the first entry defects found by a compiler rather than a judge. The first pass also showed the superset manifests must carry the libraries the knowledge base recommends: 13 A and 20 B failures were missing packages, not slips, until added. Judged: A 1.80/1.76, B 1.91/1.74, clean 256 -> 263; B ahead on fix_quality for 64 cases and behind on 22; no_harm level, with B's unanimous losses in allowlists the CWE-77/78/90 entries prescribe and the rubric pin scores as narrowing, and in whole-file rewrites that changed something beside the sink. The gate dominates the judges' own compiling (11 unanimous 2.00s were compile errors; no gate-OK write-up drew a compile claim that held), so from run 18 the judges receive the gate line and stop compiling | [RESULTS-v17.md](RESULTS-v17.md) |
| 18 | Targeted: 115 cases whose entries changed after run 17 - every CWE-22/77/78/90 case (allowlists no longer a default step) and the Java cases of the entries that gained package names; run 17's A and B text for the same cases re-judged beside a fresh guided sample, judges given the gate's Build line and told not to compile | 345 (115 x 3 sets) | Do the package names remove the build failures, and does dropping the default allowlist recover the guided arm's no_harm? | Package set (37 Java cases): guided 1.53/1.60 -> 1.84/1.81, build failures 8 -> 3, missing imports 5 -> 0. Doctrine set (78): the guided arm stopped adding allowlists (anchored regexes 9 -> 0, unanimous narrowing verdicts 12 -> 2) and no_harm stayed flat (1.66 -> 1.68) because silent behaviour changes from shell-elimination rewrites took the vacated place; CWE-90 recovered (1.70 -> 1.90), CWE-78 did not (1.54). Judges obeyed the Build line 19 of 19 and cost the same per write-up | [RESULTS-v18.md](RESULTS-v18.md) |
