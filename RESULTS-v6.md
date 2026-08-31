# Validation harness - run 6 results

6 runs (3 cases x 2 arms) on the three `authored-from-docs-pitfall` cases run 4 left unrun:
`OrderEventQueueDeserialize` (CWE-502, Java), `ModelCachePickleLoad` (CWE-502, Python),
`DeprecatedEntityLoaderGuard` (CWE-611, PHP). Same harness, same judge rubric, three independent
judges scoring all six blind. Executed the same way as run 5: HARNESS.md's prompts verbatim,
orchestrated as a workflow.

| Set | n | fix /2 | no-harm /2 |
|---|---|---|---|
| A - no guidance | 3 | 2.00 | 1.78 |
| B - skill | 3 | 1.89 | 1.44 |

At n=3 these aggregates are not the finding - every cell above is one or two runs. What matters is
what happened in each of the three, and none of it is the trap catching the guided arm the way it
was built to.

## OrderEventQueueDeserialize (CWE-502, Java): trap avoided cleanly, 2.00/2.00 both arms

Both arms used an `ObjectInputFilter` allowlist and both judges who compiled and ran it confirmed
it works: a legitimate `OrderEvent` deserializes, a disallowed class is rejected. Nothing else to
report - the entry's Java guidance holds up plainly here.

## DeprecatedEntityLoaderGuard (CWE-611, PHP): the trap caught the *un*guided arm

Both arms shipped the same code fix (drop `LIBXML_NOENT`, add `LIBXML_NONET`), so `fix_quality` is
2/2 for both. They disagree sharply on why:

- **Arm A (no guidance)** argued the finding is **not exploitable**: since libxml 2.9.0 / PHP 8.0,
  external entity resolution is disabled by default, so (its reasoning went) `LIBXML_NOENT` only
  affects already-resolved entities and cannot itself cause a `SYSTEM` identifier to be fetched.
- **Arm B (guided)** argued the finding **is exploitable**: `LIBXML_NOENT` re-enables entity
  substitution despite its name, which reopens exactly the path the PHP 8.0+ default closed - and
  it correctly scoped the fix to the case's stated `php: ^8.2`, noting that `LIBXML_NO_XXE` (the
  flag that closes this gap even with `LIBXML_NOENT` set) needs 8.4+/libxml 2.13+ and so isn't
  assumed available.

Two of three judges independently reproduced arm B's read and confirmed it. `cwe/611/php/INDEX.md`
already documents this exact mechanism - it states `LIBXML_NO_XXE` is needed specifically because
`LIBXML_NOENT` "otherwise reopens XXE" even with the modern default - so the guided arm's Verdict
section matches the entry precisely. `no_harm` splits accordingly (A: 1.67, B: 2.00): both arms
shipped the same fix, but only one described it accurately, even though the case's own prompt
states the finding is confirmed real. This is the run's one clean instance of guidance improving
output the trap did not have to catch a fix defect to demonstrate.

**This was directly reproduced, not left as a judge self-report** (see the no_harm rubric section
below for why that distinction turned out to matter): a minimal script against PHP 8.5.8/libxml
2.11.9 confirmed `DOMDocument::loadXML($xml, LIBXML_NOENT)` resolves an external `SYSTEM` entity and
leaks the target file's contents, and that dropping `LIBXML_NOENT` returns the same entity to an
empty string. Arm B and the entry are correct; arm A's "not exploitable" verdict is wrong.

## ModelCachePickleLoad (CWE-502, Python): the intended trap failed for both arms - a different, worse one appeared, and it hit the guided arm harder

Neither arm took the bait of replacing `pickle` with `json.loads()` wholesale - the trap this case
was built around. Both independently landed on exactly what `cwe/502/python/INDEX.md`'s Key
Principles already recommend for a "trusted-but-tampered channel": a restricted `Unpickler` paired
with an HMAC signature. That guidance is doing its job; the entry does not need a fix here.

Where they differ is what happens next. Both fixes need a companion change outside the reported
file - the nightly batch job must start HMAC-signing its cache writes - and both wrote that
dependency down explicitly rather than hiding it. But the restricted `Unpickler` also needs an
allowlist of permitted classes, and the case file never states what the real model class is:

- **Arm A (no guidance)** guessed concrete class names (`sklearn`/`numpy`) not evidenced anywhere
  in the case, presented with a caveat that they were unverified. The guess makes the endpoint
  function, on an assumption that might be wrong.
- **Arm B (guided)** declined to guess, shipped `_ALLOWED_MODEL_CLASSES` as an explicit empty set
  with an instruction comment to populate it, and named the same assumption plainly in its own
  Verdict section (lowered confidence, stated the gap).

Judges scored the honest-but-broken placeholder far worse (`no_harm` 0.33) than the confident,
unverified guess (`no_harm` 1.67) - every legitimate request 502s under B until a developer fills
in the allowlist, and the rubric asks whether the endpoint still works for a legitimate caller,
disclosed or not.

This sharpens a gap README.md already names: `no_harm` doesn't yet distinguish disclosed
incompleteness from silent breakage. Run 4 found this cuts against declared scope creep (an added
guard clause, a widened cap); this run finds it cuts just as hard against declared *caution* - a
model that says "I don't know the real class name, here's where to add it" scores as though it
broke the endpoint by accident, identically to if it had.

## Addendum: fixing the no_harm disclosure gap, and what testing it found

The `no_harm` disclosure gap above was closed in HARNESS.md: the rubric now scores a fix that stops
legitimate use but says so plainly as a 1, not a 0 - disclosure moves a 0 to a 1, not a 0 to a 2, so
a genuinely broken fix still cannot score clean. Validated cheaply by re-judging the same six
run-6 write-ups, blind, with three fresh judges under the new wording (no new remediation needed -
same blind pool, same case files):

| run | case, arm | old no_harm | new no_harm |
|---|---|---|---|
| R103 | ModelCachePickleLoad, B (disclosed empty allowlist) | 0.33 | 1.00 |
| R104 | ModelCachePickleLoad, A (undisclosed guessed classes) | 1.67 | 0.33 |

Both moved the direction the fix intends: the disclosed, broken-until-configured fix rose, and the
undisclosed, silently-maybe-wrong guess fell sharply - the new panel called out that four fabricated
class names presented as fact, unverified anywhere in the case, will likely break real model loads
with no warning. That is a second, independent confirmation of run 6's headline finding about
`ModelCachePickleLoad`, from a different angle.

But the same re-judge also reversed the *other* case's technical read with no rubric change involved
- the new panel unanimously agreed with arm A's wrong "not exploitable" verdict, citing a
reproduction that (per the direct reproduction above) cannot have been done correctly. `R101` and
`R106` (`OrderEventQueueDeserialize`) also drifted down slightly on an unrelated, more defensible
disagreement about how much of `OrderEvent`'s allowlist the write-up should have hedged. Judge-panel
variance on a borderline call is not a rubric problem and not new to this run, but a full unanimous
reversal on a load-bearing technical claim is - see HARNESS.md's new "Things that have gone wrong
before" entry. The practical implication: a judge's stated reproduction is not itself verified, and
should not be trusted over a conflicting result without redoing it independently, which is what
settled this one.

The rubric wording change applies to runs from here forward; runs 1-6's `no_harm` numbers were
scored under the old wording and are not directly comparable without accounting for that, the same
way run 3 kept its pre/post SKILL.md-fix numbers in separate columns rather than merging them.

## What run 6 establishes

1. **12 of 13 `authored-from-docs-pitfall` cases across runs 4 and 6 do not catch the trap as
   designed.** `fix_quality` stayed at or near ceiling in every case here too. Only CWE-117/java
   (run 4) has caught the guided arm the way the batch intended; this run adds zero more instances
   of that design working, and the remaining two CWE-502 cases in this run instead surfaced
   unplanned findings.
2. **One clean, independently-verified case of guidance measurably improving accuracy on a
   contested technical claim.** `DeprecatedEntityLoaderGuard`'s guided arm gave the answer that
   matched the entry's documented mechanism, confirmed by direct reproduction (see the addendum);
   the ungoverned arm argued the opposite and was wrong, despite the prompt stating the finding was
   confirmed real.
3. **The `no_harm` disclosure gap generalised beyond scope creep, and is now fixed.** Run 4 found
   declared scope creep cost a point under the old rubric. Run 6 found declared, honest
   incompleteness cost more - a model that refuses to guess a class name it cannot verify scored
   worse than one that guesses and gets lucky. HARNESS.md's rubric now scores a disclosed,
   endpoint-breaking limitation as a 1 rather than a 0; the addendum above validates the fix moved
   the two affected runs in the intended direction without inflating a genuinely broken fix to a 2.
4. **A judge's self-reported reproduction is not reliable evidence on its own.** Re-judging the same
   evidence with a fresh panel produced a confident, unanimous, wrong reversal of
   `DeprecatedEntityLoaderGuard`'s technical read - not a close call, a full flip - most likely from
   a Windows `file://` URI construction bug that silently reads as "the entity didn't resolve."
   HARNESS.md's "Things that have gone wrong before" now names this; treat any single judge panel's
   "reproduced" claim as provisional until checked independently, especially before it changes an
   entry.

## Limitations

- **n = 3 cases, one per CWE/language cell except CWE-502 (2).** Every finding above is a single
  run, credible only because of unanimous or 2-of-3 judge agreement, not sample size.
- **These cases are `authored-from-docs-pitfall`** - their `trap`/`must_preserve` fields are an
  authoring claim, not external ground truth. `DeprecatedEntityLoaderGuard`'s core technical
  question was independently settled by direct reproduction (see above and the addendum); the other
  two cases' claims still rest on judge reasoning that was not independently re-verified.
- **`must_preserve` was not passed to the judges**, per the same unresolved gap runs 4 and 5 both
  flagged.
- **Most reproduction claims in this run are still judge self-reports, not independently verified.**
  The one exception is `DeprecatedEntityLoaderGuard`, checked directly against PHP 8.5.8/libxml
  2.11.9 after two independent judge panels disagreed with each other about it - see the addendum.
  That disagreement is the reason to treat any other "reproduced" claim in this file with the same
  suspicion until it is checked the same way.
