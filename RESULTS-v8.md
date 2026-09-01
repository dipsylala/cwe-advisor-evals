# Validation harness - run 8 results

406 runs (203 cases x 2 arms) - the full current corpus, not a re-run of a fixed prior set. Run 7
tested Haiku 4.5 against Sonnet-5 judges on 79 cases; the corpus has since grown to 203 cases across
26 CWEs and 9 languages (new `authored-top15-fix-complexity` batches and 11 multi-file depth cases).
This run repeats run 7's model pairing - **Haiku 4.5 for both arms, Sonnet 5 for all judges** - on
the full corpus, so it answers "does the knowledge base still earn its place at this model size once
the corpus is much bigger and includes deliberate wrong-fix traps," not "does run 7 replicate
exactly." Treat any comparison to run 7's numbers as directional, not a controlled before/after -
see **Limitations**.

## Answer: roughly tied on fix_quality, a small no_harm edge to the unguided arm

| Set | n | fix /2 | no-harm /2 |
|---|---|---|---|
| A - no guidance | 203 | 1.86 | 1.86 |
| B - skill | 203 | 1.86 | 1.80 |

This does not repeat run 7's headline (1.84 vs 1.97 fix_quality, a clear gap favouring guidance) on
the same model pairing. The most likely reason is corpus composition, not a reversal of run 7's
mechanism: run 8 adds 55 `authored-top15-fix-complexity` cases and 13 `authored-from-docs-pitfall`
cases, each built around a plausible-but-wrong fix or a partial mitigation, and both arms take
damage on those (`authored-top15-fix-complexity` A=1.79/B=1.84, `authored-from-docs-pitfall`
A=1.62/B=1.74 - B still ahead on both, just not enough to move the aggregate). The run 7 corpus's
own CWE-90 result inverted outright (see below), for a mechanism this run traced to source, not
merely observed.

Judge disagreement: 50/406 (12.3%) on `fix_quality`, 74/406 (18.2%) on `no_harm` - both higher than
run 7's 15/158 (9.5%) and 21/158 (13.3%). Some of this is the judging methodology change (see
**Limitations**); some of it is a harder corpus with more genuine defects to disagree about, as the
verified findings below show judges catching real, non-obvious compile errors in both arms.

## Verified findings that changed the knowledge base

Three defects were confirmed by direct inspection of the actual arm output and the real
API/language/framework semantics, not taken from a judge's word, and all three are now fixed in the
guidance itself.

### `cwe/90/java`: the parameterized `DirContext.search()` overload judges (and both arms) kept getting wrong

Three of four Juliet CWE-90 multi-file cases (`Case07`, `Case08`, `Case09`) show the same pattern:

| case | depth | A fix | B fix |
|---|---|---|---|
| Case07 | 2 | 2.00 | 0.67 |
| Case08 | 4 | 2.00 | 0.67 |
| Case09 | 5 | 2.00 | 0.67 |
| Case17 | 2 | 2.00 | 2.00 |

Reading the actual write-ups (not just the judge notes): arm A (no guidance) sidestepped the JNDI
parameterized API entirely and hand-wrote an RFC 4515 escaper - a valid, if manual, fix. Arm B
(guided) followed the entry's instruction to "pass user input via the `filterArgs` parameter of
`DirContext.search()`" and wrote:

```java
directoryContext.search("", search, new String[]{data});
```

This is a three-argument call. `javax.naming.directory.DirContext` has no such overload - every
overload that accepts `filterArgs` also requires a trailing `SearchControls` argument. This does not
compile, in all three cases, independent of the judge panel that caught it (three different shards,
three different judges, same finding). The entry never stated the actual argument shape, so the
model filled the gap with a plausible-but-nonexistent 3-arg signature - exactly the "concrete syntax
an LLM cannot derive" gap CLAUDE.md's Remediation Claims section names as this repo's most common
recurring defect.

**Fixed**: `cwe/90/java/INDEX.md`'s Remediation Steps now states the real signature
(`search(name, filterExpr, filterArgs, cons)`), says explicitly that there is no three-argument
overload, and tells the model to supply `new SearchControls()` when the existing call does not
already build one.

### `cwe/117/javascript`: naming Unicode code points by U+XXXX without showing the JS escape to write them

`WinstonUserInputLog` (depth 1): arm B scored 1.00/1.00 against arm A's 2.00/2.00. The guided fix's
own generated code embedded the literal raw Unicode characters for U+0085/U+2028/U+2029 directly
inside a regex literal's replacement patterns, instead of the JS escape sequences `\u0085`, `\u2028`,
`\u2029`. U+2028/U+2029 are ECMAScript LineTerminator code points; embedded raw inside a regex
literal in that position they throw a `SyntaxError` and break the whole file at load time - confirmed
by inspecting the actual bytes of the arm's generated file, not just the judges' description of it.

The entry names these code points using U+XXXX notation (correct for prose) but never showed the
corresponding JS source-code escape, so the model had to translate "U+2028" into working JavaScript
unassisted and got it wrong. **Fixed**: the Remediation Steps' encode bullet in
`cwe/117/javascript/INDEX.md` now spells out the literal JS escape sequences (`\x00` through `\x1F`,
`\x7F`, `\u0085`, `\u2028`, `\u2029`) and states plainly that a raw, unescaped LineTerminator character
pasted into a regex or template literal is itself a syntax error.

### `cwe/352/csharp`: `app.UseAntiforgery()` does not validate a JSON-bound minimal API endpoint

`MinimalApiEmailNoAntiforgery` (depth 2): judges independently flagged the *same* defect in **both**
arms - R251 (arm A, unguided) and R363 (arm B, guided) both added `app.UseAntiforgery()` to the
pipeline, and multiple judges in both shards said the endpoint stays exploitable because it binds
its body from JSON via `EmailChangeRequest request` with no `[FromForm]`. Checked against Microsoft's
own current documentation (learn.microsoft.com, `anti-request-forgery`, retrieved this session), not
a judge's word: "a JSON API endpoint that binds its body from JSON... isn't rejected automatically on
a cross-origin request. The verdict is still recorded... but nothing enforces it." `UseAntiforgery()`
only auto-validates minimal API endpoints binding form data (`IFormCollection`/`IFormFile`/
`[FromForm]`); a JSON-bound endpoint needs an explicit `await antiforgery.ValidateRequestAsync(context)`
call inside the handler, using an injected `IAntiforgery`.

The entry's Key Principles already state that "API endpoints that accept JSON still need the check,"
but the following bullet on minimal APIs said only that they're "covered instead by
`app.UseAntiforgery()`," with nothing connecting the two - a model reading straight through finds no
signal that the JSON case needs a second, separate call. Both arms independently hit exactly that
gap, which is why the defect shows up on both sides of the blind pool for the same case rather than
only on the guided one. **Fixed**: `cwe/352/csharp/INDEX.md` now states explicitly that
`UseAntiforgery()`'s automatic check does not reach JSON-bound endpoints and names the
`IAntiforgery.ValidateRequestAsync()` call needed to close it, in both Key Principles and Remediation
Steps.

All three fixes pass `python scripts/lint.py` with no new errors.

## Harness bugs found and fixed during this run

Preparing the full 203-case corpus surfaced two latent bugs in `evals/scripts/blind.py`, both now
fixed and both worth knowing about for any future run:

1. **Case-id collision across languages.** Three ids are reused for analogous cases in different
   languages (`MultiFileRedisCommandRelay` csharp+python, `RedisMultiArgRawSocket` csharp+python,
   `MultiFileControllerRelayXss` java+php) - all new since run 7. `load_cases()` keyed its dict by
   bare id, so one language's case metadata silently overwrote the other's, and a flat
   `runs-v8/{arm}/{id}.md` output layout would have let one language's write-up file overwrite the
   other's on disk. Fixed by keying on `(cwe, language, id)` and switching the arm output layout to
   `runs-v8/{arm}/{cwe}/{language}/{id}.md`, which makes the collision structurally impossible
   rather than merely avoided.
2. **`--out` path collision with the repo's own `arm-map.json`.** The script wrote its map to
   `dirname(--out)/arm-map.json` - safe for every prior run's `--out /tmp/blind-vN`, but this run
   used a repo-local `--out evals/blind-v8`, whose dirname is `evals/`, silently overwriting run 1's
   original `evals/arm-map.json` on the first `blind.py` invocation. Caught immediately via
   `git status`, restored from git, and fixed the script itself to write the map inside `--out`
   (`<out>/arm-map.json`) so the collision cannot recur regardless of where `--out` points.

## Judging methodology deviation

HARNESS.md Step 5 specifies at least three judges, each scoring the *whole* blind pool. At 406
write-ups, one judge reading the entire pool plus verifying against case files in a single context
was judged too large to do reliably. Instead: the pool was split into 11 shards of ~40 items each
(chunked in the already-randomised rid order, so each shard is still a random cross-section of
arms/CWEs/languages), with 3 independent judges scoring each shard. This preserves the
three-independent-judges structure and blind cross-checking *within* each shard, but it means this
run is really 11 independent 3-judge panels rather than one 3-judge panel spanning the whole corpus
- panel-to-panel calibration drift is a plausible contributor to the higher disagreement rate noted
above, on top of the corpus being genuinely harder. A future run at this scale should either keep
this sharding (documented, not hidden) or explicitly test whether shard size affects the numbers.

## By CWE (selected)

| CWE | n | A fix | B fix | A no-harm | B no-harm |
|---|---|---|---|---|---|
| 90 (LDAP injection) | 10 | 1.73 | 1.60 | 1.67 | 1.63 |
| 117 (log injection) | 5 | 1.00 | 1.40 | 2.00 | 1.60 |
| 79 (XSS) | 32 | 1.90 | 1.94 | 1.90 | 1.94 |
| 89 (SQL injection) | 25 | 1.95 | 1.85 | 1.93 | 1.68 |
| 78 (OS command injection) | 12 | 1.97 | 1.97 | 1.94 | 1.86 |
| 611 (XXE) | 6 | 2.00 | 1.83 | 1.94 | 1.67 |
| 862 (missing authz) | 5 | 1.40 | 1.40 | 1.40 | 1.87 |

CWE-90's reversal from run 7 (where it was the single largest effect: A=1.11, B=2.00, n=3) is the
one traced above to source - both the entry's gap and both arms' actual generated code, not judge
notes. The rest of the by-CWE table has too few cases per cell (n=3 to n=10 outside the largest
CWEs) to read individual deltas as more than noise.

Full by-CWE, by-language, by-source, and per-run tables are not committed separately - regenerate
them from the committed `arm-map-v8.json` and `scores-v8/*.json` with:
`python scripts/analyse.py --map evals/arm-map-v8.json --scores evals/scores-v8 --out <path>`

## What run 8 establishes

1. **The knowledge base's effect is not a fixed, model-level constant** - it moves with corpus
   composition. Run 7's clean fix_quality gap on 79 cases does not reappear on the same model
   pairing once the corpus roughly triples and adds cases purpose-built to have a plausible wrong
   fix. That is consistent with run 7's own framing ("one data point on one smaller model, not the
   effect") rather than contradicting it.
2. **The knowledge base can be the source of a defect it exists to prevent**, not just a passive
   backstop against the model's own mistakes. Both verified findings above are the guided arm
   failing in a way the *unguided* arm did not, because the guidance told it to do something without
   fully specifying how - the CWE-90/java and CWE-117/javascript fixes close that gap for future
   runs, but the general lesson (name the concrete syntax, don't assume translation) is already
   documented in CLAUDE.md's Remediation Claims section and this run adds two more confirmed
   instances to it.
3. **`no_harm` now favours the unguided arm overall** (1.86 vs 1.80), a small reversal from run 5/6's
   Sonnet-5 result and from run 7's near-tie. Both of this run's verified defects are `no_harm`-shaped
   (a fix that doesn't compile is scored 0 on both criteria under the rubric), so at least part of
   this reversal is directly explained rather than a new, separate finding.

## Limitations

- **Not a controlled replication of run 7.** Same model pairing, very different corpus (79 vs 203
  cases, different CWE mix, added trap-style cases). Any run 7-vs-run 8 comparison is directional.
- **Judging was sharded (11 x 3), not one panel over the whole pool**, for context-size reasons - see
  **Judging methodology deviation** above. This is a documented deviation from HARNESS.md Step 5's
  literal instruction, not an oversight, but it does mean the disagreement-rate comparison to prior
  runs is not apples-to-apples.
- **Higher judge disagreement than run 7** (12.3% vs 9.5% on fix_quality) - some of that is the
  sharding change, some is a harder corpus; this run cannot separate the two causes.
- **Only three defects were independently verified against ground truth** (real JDK API surface, real
  ECMAScript grammar, current Microsoft ASP.NET Core docs); the rest of this run's specific per-case
  claims rely on judge notes, per the standing caution from run 6 about not trusting a judge's
  self-reported claim without independent
  verification.
- **`must_preserve` still not passed to judges** - same known gap as every prior run; the judge
  prompt does not see the case-authored contract, only what a judge infers from the code.
- **Nothing in the corpus is compiled or executed by the harness itself** - both verified findings in
  this run required a human-directed reproduction step (reading the actual generated file's bytes,
  checking the real API), which is exactly the gap README.md's Known Gaps section already names.
