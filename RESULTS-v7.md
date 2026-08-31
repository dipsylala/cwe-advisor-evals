# Validation harness - run 7 results

158 runs (79 cases x 2 arms) - the identical corpus and case list as run 5, re-run on a different
model to test whether run 5's saturation was a property of the corpus or a property of the model.

**Model: Haiku 4.5 for both arms; judges pinned to Sonnet 5** (unlike run 5/6, explicitly set per
HARNESS.md's model note, not inherited). Judges scored the same rubric as run 5/6, including the
no_harm disclosure fix. Judge disagreement was markedly higher than run 5 (`fix_quality` 15/158,
`no_harm` 21/158, vs. run 5's 2/158 and 5/158) - expected, since Haiku's output is far less uniform
and gives judges more genuine defects to weigh differently, not a sign of a broken rubric.

## Answer: at this model size, the knowledge base earns its place

| Set | n | fix /2 | no-harm /2 |
|---|---|---|---|
| A - no guidance | 79 | 1.84 | 1.83 |
| B - skill | 79 | 1.97 | 1.85 |

Run 5 found `fix_quality` saturated at 2.00/2.00 on this exact corpus under Sonnet 5 - guidance had
nothing to add because the bare model already got every case right. Under Haiku, arm A drops to
1.84 and arm B recovers most of the gap to 1.97. The aggregate hides where the effect actually
lives: it is not spread evenly, it is concentrated in a handful of CWEs where the ungoverned arm
fails hard and the guided arm does not.

| CWE | A fix /2 | B fix /2 | gap |
|---|---|---|---|
| CWE-90 (LDAP injection) | 1.11 | 2.00 | +0.89 |
| CWE-117 (log injection) | 1.25 | 2.00 | +0.75 |
| CWE-79 (XSS), python only | 0.67* | 2.00 | - |
| CWE-209 (error disclosure) | 1.78 | 2.00 | +0.22 |
| CWE-79 (XSS), all languages | 1.75 | 1.98 | +0.23 |

*python subset of CWE-79's 19 cases, not the CWE-79 row average - see below.

By language, the same pattern: **python fix_quality rose from 1.51 to 2.00**, the single largest
per-language effect in the whole run. Every other language moved less or stayed flat.

## What arm A actually did wrong - verified independently, not taken from the judges' word

Two failure shapes account for nearly all of it.

**Hallucinated library APIs.** Both CWE-90 (LDAP injection) cases in Python and JavaScript failed
the same way: arm A wrote a call to a function that does not exist in the named library.

- `LdapFilterConcat` (python): arm A wrote `from ldap3 import ..., escape_filter_chars` - importing
  it from the top-level package. **Verified directly**: `pip install ldap3` (2.9.1) and
  `hasattr(ldap3, 'escape_filter_chars')` returns `False`. The function only exists at
  `ldap3.utils.conv.escape_filter_chars`. Arm A's fix raises `ImportError` and does not run. Arm B
  wrote `from ldap3.utils.conv import escape_filter_chars` - the correct path.
- `LdapFilterFromQuery` (javascript): arm A wrote `ldap.escapeFilterValue(username)`. **Verified
  directly**: downloaded `ldapjs@3.0.7` from npm and grepped the entire package source - no
  `escapeFilterValue` anywhere in it. The function does not exist in this library, in any version
  shipped as 3.0.7. Arm B did not call a named library function at all; it hand-wrote an RFC 4515
  escaping function, sidestepping the risk of citing an API it could not verify.

Neither fabrication is exotic - both function names are exactly the shape a real escaping helper in
these libraries would have, which is what makes them the kind of error a code reviewer skimming the
diff would not catch either. `cwe/90/python/INDEX.md` and `cwe/90/javascript/INDEX.md` name the real
functions explicitly in their `Taint Sinks`/`Key Principles` sections; arm B's access to that text is
the plausible mechanism, though this run did not instrument which guidance line each write-up
actually cited.

**A fix that looks like the textbook pattern but doesn't do the job.** `LoggingFstringInjection`
(CWE-117, python): arm A replaced `logger.warning(f"...{username}")` with
`logger.warning("...: %s", username)` - the standard "always parameterize" advice, borrowed from SQL
injection where parameterization is a structural fix. For log injection it is not: Python's `%s`
substitution does not escape or strip control characters, so a `username` containing `\n` still
forges a fake log line - the fix is cosmetically different from the vulnerable code and functionally
identical. Arm B used `logger.warning("...: %s", repr(username))` - `repr()` escapes control
characters into visible sequences (`\n` becomes the two characters `\`+`n`), which actually closes
the forging vector. This is a plain reading of `repr()`'s documented behaviour, not a judge claim.

## The guided arm is not immune to the same failure shape

`GuidNewGuidToken` (CWE-330, csharp) is the one case where arm B scored clearly worse (1.00/1.33)
than arm A (2.00/2.00). Arm B's primary fix used
`System.Buffers.Text.Base64Url.ConvertToString()` - a real API, but added in .NET 9, with a caveat
appended for older targets ("If targeting .NET < 9, use..."). The case does not state a target
framework, so whether this compiles is unverified either way; unlike the LDAP cases this was not
independently checked against a specific pinned version. It is the same underlying risk (citing an
API without confirming it applies to the actual target) surfacing once in the guided arm instead of
repeatedly in the ungoverned one - guidance reduces this failure mode, it does not eliminate it.

## Where guidance didn't help, or made no_harm worse

- **CWE-347 (JWT) no_harm is weak in both arms** (A: 1.20, B: 1.40) - `ManualJwtPayloadDecode`
  scored `no_harm` 0.33 (A) and 0.00 (B) for the same underlying issue: a hardcoded or
  guessable-fallback JWT secret. Neither arm avoided this; it looks like a property of how Haiku
  handles "you need a secret and none is given" rather than something guidance fixes or causes.
- **CWE-502 no_harm favoured A** (1.58 vs 1.25) - `NodeSerializeUnsafeDecode`'s guided fix scored
  `no_harm` 0.00: an Ajv schema that accepts only `{}`, silently discarding every real profile field,
  undisclosed. Correctly scored a 0 under the (now disclosure-aware) rubric - this is a silent
  regression, not a stated limitation.
- **CWE-326 no_harm favoured A** (1.75 vs 1.50) - two guided AES-ECB fixes introduced no_harm
  issues judges did not detail as clearly; worth a follow-up read before drawing a conclusion.

## What run 7 establishes

1. **Run 5's saturation was a property of Sonnet 5, not the corpus.** The same 79 cases, same
   prompts, same rubric, on a smaller model, produce a real 0.13-point aggregate `fix_quality` gap
   and per-CWE gaps as large as +0.89. The knowledge base has measurable value that a
   Sonnet-5-only harness cannot see.
2. **The mechanism is concrete and independently verified, not inferred from judge notes**: the
   ungoverned arm invents plausible-sounding library functions that do not exist (checked directly
   against the real `ldap3` and `ldapjs` packages), and applies a surface-level pattern
   (parameterization) that doesn't achieve the security property CWE-117 actually needs. Both are
   exactly the class of error a knowledge base naming concrete, real API calls is positioned to
   prevent - it is not (this run's evidence does not support) that Haiku can't find vulnerabilities;
   it is that Haiku is more prone to hallucinating the fix's specifics.
3. **This does not fully generalise to no_harm.** Aggregate `no_harm` barely moved (1.83 -> 1.85),
   and guidance made two CWEs (347, 502, 326) worse or no better on this criterion specifically -
   a different, less consistent picture than `fix_quality`.
4. **This should be read as one data point on one smaller model, not "the effect."** Model choice
   is now a demonstrated confound: run 5 and run 7 disagree sharply on whether the knowledge base
   matters, and the only variable that changed is the arm model. Testing a third model (a mid-tier
   one, or a different vendor) is the obvious next step before treating either run as representative.

## Limitations

- **Higher judge disagreement than run 5** (15/158 fix_quality, 21/158 no_harm vs. 2/158 and
  5/158). Expected given Haiku's less uniform output, but it means single-run per-CWE numbers with
  small n (CWE-90's n=3, CWE-209's n=3) carry more noise than run 5's equivalent cells did.
- **The mechanism claim ("arm B used the guidance's named API") is plausible, not instrumented.**
  This run did not capture which specific `cwe/` file or line each arm B write-up read before
  writing its fix, so "guidance is why B got the right function name" is an inference from the
  entries' content matching, not a traced citation.
- **Two library-API claims were verified directly against the real package** (`ldap3` 2.9.1,
  `ldapjs` 3.0.7); the rest of this file's specific claims (CWE-117's `repr()` behaviour aside,
  which is directly checkable Python semantics) rely on judge notes, per the standing caution from
  run 6 about not trusting a judge's self-reported claim without independent verification.
- **`must_preserve` was not applicable** - all 79 cases are `authored`, none carry that field.
- **This is model pair #2 of an eventual N.** One more data point does not establish a trend line;
  see point 4 above.
