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
section matches the entry precisely, and the entry's account holds up under judge reproduction.
`no_harm` splits accordingly (A: 1.67, B: 2.00): both arms shipped the same fix, but only one
described it accurately, even though the case's own prompt states the finding is confirmed real.
This is the run's one clean instance of guidance improving output the trap did not have to catch a
fix defect to demonstrate.

One caveat on the reproduction itself: one judge's note reproduces the leak "on PHP 8.5/libxml
2.11," not the PHP 8.2 the case's `composer.json` comment specifies. The conclusion still matches
the entry's documented mechanism, but a version-pinned claim reproduced against a different runtime
than the case targets is exactly the kind of drift this repo's own version-claims discipline exists
to catch - it just showed up in a judge this time, not an authored entry.

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

## What run 6 establishes

1. **12 of 13 `authored-from-docs-pitfall` cases across runs 4 and 6 do not catch the trap as
   designed.** `fix_quality` stayed at or near ceiling in every case here too. Only CWE-117/java
   (run 4) has caught the guided arm the way the batch intended; this run adds zero more instances
   of that design working, and the remaining two CWE-502 cases in this run instead surfaced
   unplanned findings.
2. **One clean case of guidance measurably improving accuracy on a contested technical claim.**
   `DeprecatedEntityLoaderGuard`'s guided arm gave the answer that matched the entry's documented
   mechanism and that two of three judges reproduced; the ungoverned arm argued the opposite,
   despite the prompt stating the finding was confirmed real.
3. **The `no_harm` disclosure gap generalises beyond scope creep.** Run 4 found declared scope
   creep costs a point under this rubric. Run 6 finds declared, honest incompleteness costs more -
   a model that refuses to guess a class name it cannot verify scores worse than one that guesses
   and gets lucky. This is the same open gap, not a new one, but it is now demonstrated in the
   direction that matters most: it can penalise the more conservative, more honest behaviour.
4. **A judge-side version-drift instance, worth a HARNESS.md note.** When a case names a target
   runtime version, a judge's reproduction should be checked against that version, not whichever one
   happens to be locally available - the conclusion here still held, but the mismatch was luck, not
   design.

## Limitations

- **n = 3 cases, one per CWE/language cell except CWE-502 (2).** Every finding above is a single
  run, credible only because of unanimous or 2-of-3 judge agreement, not sample size.
- **These cases are `authored-from-docs-pitfall`** - their `trap`/`must_preserve` fields are an
  authoring claim, not external ground truth. This run does not independently settle whether
  `cwe/611/php`'s documented `LIBXML_NOENT` mechanism is correct against a live, pinned PHP
  8.2/libxml target; it relies on judges' own stated reproduction, one of which used a different
  runtime version than the case specifies (see above).
- **`must_preserve` was not passed to the judges**, per the same unresolved gap runs 4 and 5 both
  flagged.
- **Nothing was compiled or executed by this session directly.** Every reproduction claim above is
  a judge's self-report, which is exactly where the PHP-version drift was caught - a reminder that
  a judge's "reproduced" is not independently verified either.
