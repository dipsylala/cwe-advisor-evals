# Validation harness

Validates the knowledge base in [dipsylala/cwe-advisor](https://github.com/dipsylala/cwe-advisor) -
this repo is linked into it as a git submodule at `evals/`. Every path below (`cwe/{CWE}/...`, the
`{repo}` placeholders in HARNESS.md) refers to that parent checkout, so run the harness from inside
a `cwe-advisor` clone with this submodule initialized (`git submodule update --init`), not from a
standalone clone of this repo.

## What this measures

CWE guidance in the parent repo is written and reviewed on reasoning alone - nothing is measured by
default. This harness exists to put numbers against three durable questions:

1. **Does the knowledge base beat the bare model?** If a capable model fixes SQL injection just as
   well without the entry, the entry is not earning its place, and content should shift toward
   detail a model genuinely lacks.
2. **Does review effort show up in output quality?** Tested by splitting cases between CWEs a
   review pass covered and CWEs it never touched.
3. **Does a specific content or workflow change show up in fix quality?** Tested with before/after
   comparisons on the same entries or the same SKILL.md logic.

Four runs so far - see **Past runs** below for what each one found. The headline that holds across
all of them: verdict accuracy and multi-file source tracing are saturated in every arm, at every
chain depth tested up to five files - a capable model does not need this harness's help to trace
taint or recognise a textbook vulnerability. The knowledge base's one consistently measurable effect
is on `no_harm` - whether a fix silently breaks or changes something the sink's caller depended on -
and that effect has gone in both directions depending on how an entry's `Remediation Steps` are
ordered (see run 4).

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

Current contents: 125 cases across 17 CWEs and seven languages (perl added by the CWE-79 depth
batch below). Four sources:

| `source` | n | What it is |
|---|---|---|
| `owasp-benchmark` | 16 | Single-file Java servlets, labels from `expectedresults-1.2.csv` |
| `juliet` | 17 | Java multi-file flow variants, de-labelled mechanically; taint crosses 2, 4 or 5 files |
| `authored-from-docs-pitfall` | 13 | Single-function cases across Java, Python, Go, C#, JavaScript and PHP, each built around a fix that looks right and is not |
| `authored` | 79 | Single-function, single-language, plain true-positive cases with no `trap`/`must_preserve`/`origin` - either pure language-coverage or top-15 depth (see below), not a discrimination instrument |

**`owasp-benchmark` and `juliet`** are externally authored, so their ground truth doesn't come from
this repo: Benchmark ships `expectedresults-1.2.csv`, Juliet encodes it in the variant name (then
mechanically stripped before use). A case written here would be shaped toward the guidance -
unconsciously matching the vulnerability to the form the entry already describes - which manufactures
whatever result was wanted. That is why these two are weighted as the stronger ground truth.

**`authored-from-docs-pitfall`** cases exist because runs 1-3 measured the first two sources to
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
two sources. Treat a judge disagreeing with `kind` on one of these as a finding about the case. Run
4 scored the first ten and found the traps mostly did not work (19/20 at ceiling on `fix_quality`) -
see [RESULTS-v4.md](RESULTS-v4.md). The one exception confirmed a specific, since-repeated shape:
when an entry's `Remediation Steps` open with an infrastructure or configuration change rather than
the fix at the reported sink, the guided arm tends to perform that change and leave the flagged line
untouched. Three more cases (`OrderEventQueueDeserialize`, `ModelCachePickleLoad`,
`DeprecatedEntityLoaderGuard`) target that same shape directly; none has been run yet.

**`authored`** cases come from two related but distinct campaigns, both tracked in TODO.md, neither
built around a deliberate wrong-fix:

- **Per-language coverage (breadth).** At least one case per `(CWE, language)` slot that has a
  language-specific entry. CWE-22, 78, 89, 90, 117, 209, 326, 330, 338, 347, 434, 502, 611 and 614
  are fully covered across every language their entry has.
- **Top-15 depth.** For the CWEs this project's own MITRE Top-25 ranks-1-15 review covered
  (CWE-20, 22, 77, 78, 79, 89, 94, 125, 269, 287, 352, 416, 434, 787, 862 - 20 and 269 are
  root-only and out of scope), a target of 3 cases per `(CWE, language)` slot rather than 1, each
  built from a distinct named pattern in that language's `docs/CWE-{ID}/{language}/index.md`
  "Common Vulnerable Patterns" section (adapted into an original scenario, not copied verbatim).
  CWE-79 is the first one done: all 7 of its languages (including the newly-added perl) now have
  3 cases each.

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
| `group` | `reviewed` or `unreviewed`, for the review-effort split (the CWEs the top-15 review covered - see run 1's design in [RESULTS.md](RESULTS.md) - are `reviewed`; everything else is `unreviewed`) |
| `files` | Source files, in call order |
| `finding` | What the scanner reports: `cwe`, `name`, `file`, `sink_line`, `sink_code`, `summary` |
| `trap`, `must_preserve`, `origin` | `authored-from-docs-pitfall` only. A plain `authored` case omits all three |

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
label, so nothing needs editing to add an arm or start a new run. **Pick the next unused version
suffix for a new run** (the existing ones are `runs`/`runs-v2`/`runs-v3`/`runs-v4` and their matching
`arm-map*.json`/`scores*.json`/`RESULTS*.md`); HARNESS.md's own examples are written against
`runs-v4` specifically because that is what run 4 used, not because that name is special.

### Known gaps

- **Most of the corpus has never been run.** Run 4 scored 10 cases. The corpus is now 125: the 79
  `authored` cases from the breadth and depth campaigns have been checked for realism (sink lines
  verified against the file, sink APIs matched to the entry's own `Taint Sinks` list) but never put
  through an actual arm-vs-arm, judge-scored run. That is the natural scope for a run 5.
- **`no_harm` doesn't see `must_preserve` yet.** The judge prompt in HARNESS.md withholds all of
  `case.json`, including the contract `must_preserve` states, so judges apply their own reading of
  what the original preserved and can disagree with each other over it (9 of 20 runs disagreed in
  run 4). Passing the stated contract into the judge prompt without revealing which fix is the trap
  is the obvious next fix.
- **Nothing in the corpus is compiled or executed.** A fix is scored on whether it reads as correct,
  not on whether it actually builds or passes a test.

## Past runs

| Run | Corpus | Runs | Question | Headline | Results |
|---|---|---|---|---|---|
| 1 | 16 OWASP Benchmark cases (Java) | 48 (16 x 3 arms) | Does the knowledge base beat the bare model? | Every run scored max on vulnerability-removed - the corpus was too easy to discriminate any arm. The only signal: guidance made one CWE-78 fix worse by over-deleting a feature | [RESULTS.md](RESULTS.md) |
| 2 | +17 Juliet cases (Java, chain depth 2-5, plus false positives) | 34 (17 x 2 arms) | Does multi-file taint tracing need the skill? | No - both arms traced five-file chains and declined every false positive perfectly. `no_harm` was the only criterion with variance, and it cut both ways: helped on CWE-90/601, hurt on CWE-78 | [RESULTS-v2.md](RESULTS-v2.md) |
| 3 | Same 17 Juliet cases, re-judged, plus a fresh B2 | 51 (17 x 3 sets) | Did the sink-contract fix (SKILL.md Step 4/5) address run 2's harm? | Yes - `no_harm` on true positives rose from 1.25 (A) / 1.67 (B, before) to 1.92 (B2, after); CWE-601's URI-fragment preservation is a clean, unconfounded before/after | [RESULTS-v3.md](RESULTS-v3.md) |
| 4 | +10 `authored-from-docs-pitfall` cases | 20 (10 x 2 arms) | Do the deliberately-planted "plausible but wrong" fixes actually catch anything? | Mostly no (19/20 at ceiling on `fix_quality`) - but the one that did (CWE-117) confirmed a repeatable defect shape: guidance that leads with an infrastructure/config change over the sink-level fix | [RESULTS-v4.md](RESULTS-v4.md) |
