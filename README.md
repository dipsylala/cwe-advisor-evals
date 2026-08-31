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

Seven runs so far - see **Past runs** below for what each one found. Runs 1-6 all ran on Sonnet 5
(undocumented as such until run 5/6, see the model gap below) and found verdict accuracy and
multi-file source tracing saturated in every arm at every chain depth tested up to five files, and
`fix_quality` saturated across the 79-case breadth/depth corpus too - at that model's capability
level, guidance had nothing to add to whether the vulnerability got found and closed. The knowledge
base's one consistently measurable effect on Sonnet 5 was on `no_harm` - whether a fix silently
breaks or changes something the sink's caller depended on - and that effect went in both directions
depending on how an entry's `Remediation Steps` are ordered (see run 4). Run 5 found a defect
neither arm avoided (a CWE-434 fix that renames an uploaded file without the entry warning the read
path needs the new name too, since fixed - see run 5's row below). Run 6 found the planted traps
still mostly don't catch anything (12 of 13 across runs 4 and 6), sharpened the one open `no_harm`
gap (a model that honestly declines to guess a value it cannot verify scored worse than one that
guesses and gets lucky - the rubric now scores disclosure correctly, see HARNESS.md Step 5), and
independently confirmed by direct reproduction that `cwe/611/php`'s `LIBXML_NOENT`/`LIBXML_NO_XXE`
guidance is technically correct - a re-judge with a fresh panel had disagreed, unanimously and
wrongly, which is its own finding: see HARNESS.md's **Things that have gone wrong before** and
[RESULTS-v6.md](RESULTS-v6.md)'s addendum.

**Run 7 overturns the "saturated" half of that headline.** The identical 79-case corpus, re-run
with Haiku 4.5 on both arms instead of Sonnet 5, produced a real `fix_quality` gap (1.84 no-guidance
vs. 1.97 guided; +0.89 on CWE-90 alone) that Sonnet 5 never showed on these same cases. The
mechanism was checked directly, not taken from a judge's word: the ungoverned arm called library
functions that do not exist - confirmed by installing the real `ldap3` and `ldapjs` packages and
checking - while the guided arm, reading the entry's named APIs, did not. Saturation was a property
of the model being capable enough not to need the guidance, not a property of the corpus being too
easy; see [RESULTS-v7.md](RESULTS-v7.md).

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

Current contents: 148 cases across 18 CWEs and seven languages (perl added by the CWE-79 depth
batch below). Four sources:

| `source` | n | What it is |
|---|---|---|
| `owasp-benchmark` | 16 | Single-file Java servlets, labels from `expectedresults-1.2.csv` |
| `juliet` | 17 | Java multi-file flow variants, de-labelled mechanically; taint crosses 2, 4 or 5 files |
| `authored-from-docs-pitfall` | 13 | Single-function cases across Java, Python, Go, C#, JavaScript and PHP, each built around a fix that looks right and is not |
| `authored` | 102 | Plain true-positive cases with no `trap`/`must_preserve`/`origin` - language-coverage, top-15 depth, or (11 cases, see below) multi-file chains crossing 2-5 files, not a discrimination instrument |

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
untouched. Run 6 scored the remaining three (`OrderEventQueueDeserialize`, `ModelCachePickleLoad`,
`DeprecatedEntityLoaderGuard`) and found none of them caught that shape either - 12 of 13 across
both runs now, so `authored-from-docs-pitfall` traps still mostly do not catch anything, though run
6 did surface two findings the traps were not built to test - see [RESULTS-v6.md](RESULTS-v6.md).

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
  CWE-79 was the first one done: all 7 of its languages (including the newly-added perl) have 3
  cases each. CWE-77 is the second: csharp/java/php/python (its only 4 languages) now have 3 cases
  each too, scoped strictly to the non-shell interpreters this entry covers (Redis/Memcached inline
  protocol, raw-socket SMTP/IMAP/FTP, PHP dynamic dispatch) - never a CWE-78 shell pattern, which
  would misfile the case. Remaining, in MITRE rank order: 78, 89 (both already breadth-complete at
  1/language, need 2 more per slot), 94, 125, 287, 352, 416, 434 (same), 787, 862.
- **Multi-file depth.** Every `authored` case above is single-file (`depth: 1`) - the only multi-file
  cases in the corpus were `juliet`'s, and only in Java. 11 new cases (one per language slot across
  CWE-79 and CWE-77, `depth` 2-5) test whether tracing across files - which runs 1-3 found saturated
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
suffix for a new run** (the existing ones are `runs`/`runs-v2`/`runs-v3`/`runs-v4`/`runs-v5`/`runs-v6`
and their matching `arm-map*.json`/`scores*.json`/`RESULTS*.md`); HARNESS.md's own examples are
written against `runs-v4` specifically because that is what run 4 used, not because that name is
special.

### Known gaps

- **`no_harm` doesn't see `must_preserve` yet.** The judge prompt in HARNESS.md withholds all of
  `case.json`, including the contract `must_preserve` states, so judges apply their own reading of
  what the original preserved and can disagree with each other over it (9 of 20 runs disagreed in
  run 4). Passing the stated contract into the judge prompt without revealing which fix is the trap
  is the obvious next fix. This is separate from the disclosure gap below, which is fixed.
- **`no_harm`'s disclosed-vs-silent gap is fixed going forward, not retroactively.** Runs 4 and 6
  both found the old rubric scored a disclosed limitation the same as a silent one - run 4 saw
  declared scope creep cost a point, run 6 saw a model that honestly declined to guess an
  unverifiable value score far worse than one that guessed and got lucky. HARNESS.md's `no_harm`
  wording now scores a disclosed, endpoint-breaking limitation as a 1 rather than a 0. Runs 1-6's
  `no_harm` numbers were scored under the old wording and are not directly comparable to a future
  run's without accounting for that.
- **A judge's self-reported "reproduced" is not independently verified.** Validating the disclosure
  fix on run 6's pool, a fresh judge panel unanimously reversed the original panel's (correct) read
  of `DeprecatedEntityLoaderGuard`'s core technical claim while citing its own reproduction. Direct
  reproduction confirmed the original panel and the entry were right - see HARNESS.md's **Things
  that have gone wrong before** and [RESULTS-v6.md](RESULTS-v6.md)'s addendum. Treat a judge's
  reproduction claim as provisional, especially before it would change an entry.
- **Nothing in the corpus is compiled or executed by the harness itself.** A fix is scored on
  whether it reads as correct, not on whether it actually builds or passes a test; the judge-side
  gap above is this same problem one level up, where even the *scoring* wasn't independently
  verified until this session checked one case by hand.
- **Model has been varied exactly once.** Runs 1-6 all had every arm and judge inherit whatever
  model was running the orchestrating session (Sonnet 5 for runs 5 and 6, undocumented for 1-4).
  Run 7 re-ran run 5's exact corpus with arms on Haiku 4.5 and judges pinned to Sonnet 5, and found
  a real `fix_quality` gap Sonnet 5 never showed on the same cases - see run 7's row below. That is
  one data point on one smaller model, not a trend; a third model (mid-tier, or a different vendor)
  is the obvious next test before treating either result as representative.

## Past runs

| Run | Corpus | Runs | Question | Headline | Results |
|---|---|---|---|---|---|
| 1 | 16 OWASP Benchmark cases (Java) | 48 (16 x 3 arms) | Does the knowledge base beat the bare model? | Every run scored max on vulnerability-removed - the corpus was too easy to discriminate any arm. The only signal: guidance made one CWE-78 fix worse by over-deleting a feature | [RESULTS.md](RESULTS.md) |
| 2 | +17 Juliet cases (Java, chain depth 2-5, plus false positives) | 34 (17 x 2 arms) | Does multi-file taint tracing need the skill? | No - both arms traced five-file chains and declined every false positive perfectly. `no_harm` was the only criterion with variance, and it cut both ways: helped on CWE-90/601, hurt on CWE-78 | [RESULTS-v2.md](RESULTS-v2.md) |
| 3 | Same 17 Juliet cases, re-judged, plus a fresh B2 | 51 (17 x 3 sets) | Did the sink-contract fix (SKILL.md Step 4/5) address run 2's harm? | Yes - `no_harm` on true positives rose from 1.25 (A) / 1.67 (B, before) to 1.92 (B2, after); CWE-601's URI-fragment preservation is a clean, unconfounded before/after | [RESULTS-v3.md](RESULTS-v3.md) |
| 4 | +10 `authored-from-docs-pitfall` cases | 20 (10 x 2 arms) | Do the deliberately-planted "plausible but wrong" fixes actually catch anything? | Mostly no (19/20 at ceiling on `fix_quality`) - but the one that did (CWE-117) confirmed a repeatable defect shape: guidance that leads with an infrastructure/config change over the sink-level fix | [RESULTS-v4.md](RESULTS-v4.md) |
| 5 | 79 `authored` cases (breadth + depth campaigns, 14 CWEs x 7 languages) | 158 (79 x 2 arms) | Does the knowledge base still help on the ordinary, undramatic, single-file case at this scale? | `fix_quality` saturated again (156/158 at ceiling); `no_harm` favoured the guided arm on a low-disagreement measurement (1.97 A vs 2.00 B); found one new, reproducible entry gap - `cwe/434/go` doesn't warn that a renamed upload needs the read path updated too, and both arms independently shipped that break | [RESULTS-v5.md](RESULTS-v5.md) |
| 6 | Last 3 `authored-from-docs-pitfall` cases | 6 (3 x 2 arms) | Do the last three planted traps catch anything run 4 didn't already find? | No (12/13 across runs 4 and 6 at ceiling on `fix_quality`), but two unplanned findings: guidance gave the technically correct exploitability read on a contested PHP/libxml question two judges reproduced, and the `no_harm` disclosure gap cuts against honest incompleteness even harder than it cuts against declared scope creep | [RESULTS-v6.md](RESULTS-v6.md) |
| 7 | Run 5's identical 79 cases, arms on Haiku 4.5 instead of Sonnet 5 (judges stayed on Sonnet 5) | 158 (79 x 2 arms) | Does run 5's `fix_quality` saturation hold on a smaller model? | No - real gap (1.84 A / 1.97 B), concentrated in CWE-90 (+0.89) and CWE-117 (+0.75). Mechanism verified directly, not from judge notes: the ungoverned arm called `ldap3`/`ldapjs` functions that do not exist (confirmed against the real packages); the guided arm, reading the entry's named APIs, did not | [RESULTS-v7.md](RESULTS-v7.md) |
