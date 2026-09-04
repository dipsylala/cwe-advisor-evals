# Validation harness - run 13 results

744 runs (372 cases x 2 arms) - run 11's identical corpus (last `cases/` commit `ee0bb0c`, before
run 11), **Haiku 4.5 for both arms**, Sonnet 5 judges, byte-identical run-11 arm prompt. Two things
changed since run 11: the twelve entries edited after runs 11 and 12 (`cwe/502` root/java/php/go,
`cwe/352` root/go/java/javascript, `cwe/434/javascript`, `cwe/125/cpp`, `cwe/79/java`,
`cwe/330/go`), and the judge header now carries each case's `must_preserve` contract. This is the
corpus-wide before/after on the edits, and the first full-corpus measurement of the contract header.

## Answer: the edits hold where they were aimed; the contract header exposes a guided `no_harm` edge

| Set | n | fix /2 | no-harm /2 | clean (2.00/2.00, all judges) |
| --- | --- | --- | --- | --- |
| run 11 A | 372 | 1.82 | 1.81 | 268 |
| run 11 B | 372 | 1.89 | 1.79 | 269 |
| run 13 A | 372 | 1.79 | 1.76 | 248 |
| run 13 B | 372 | 1.88 | 1.77 | 265 |

The gap widens slightly on `fix_quality` (+0.07 -> +0.09) and `no_harm` turns level (-0.02 -> +0.01).
Both aggregates are within the movement arm A shows with nothing changed, so - as in run 12 - the
result is in the split by slot, not the totals:

| Slice | Set | run 11 | run 13 | clean |
| --- | --- | --- | --- | --- |
| 47 cases in edited slots | A | 1.77 / 1.75 | 1.77 / 1.60 | 29 -> 24 |
| | **B** | 1.76 / 1.57 | **1.90 / 1.82** | **24 -> 32** |
| 325 cases in untouched slots | A | 1.82 / 1.82 | 1.79 / 1.78 | 239 -> 224 |
| | B | 1.91 / 1.83 | 1.88 / 1.76 | 245 -> 233 |

On the edited slots the guided arm moved +0.14 fix / +0.25 no_harm and gained 8 clean cases while the
unguided arm stayed flat on fix and fell on no_harm. On the untouched slots both arms drifted down
by the same amount (-0.03 fix, -0.04 to -0.07 no_harm) - arm A cannot see the edits, so that is the
fresh-sample and fresh-panel floor, and B's untouched drift sits inside it.

## Verified: the 13 run-11 targets, guided arm run 11 -> run 13

| Case | run 11 | run 13 | |
| --- | --- | --- | --- |
| 502/java `OrderEventQueueDeserialize` | 1.00/0.00 | **2.00/2.00** | per-stream `setObjectInputFilter` |
| 502/php `CartCookieDecodeUnserialize` | 2.00/1.00 | 1.67/2.00 | one judge wanted `false` narrowed |
| 502/php `CartLegacySerializedMigration` | 1.67/1.00 | 2.00/1.33 | format kept; dual-format read still partial |
| 502/go `JobQueueGobPrivilegeField` | 2.00/1.00 | **2.00/2.00** | narrow DTO, gob kept |
| 502/go `GobDecodeUntrustedPayload` | 2.00/1.33 | **2.00/2.00** | |
| 352/go `GetRequestStateChange` | 2.00/0.00 | **2.00/2.00** | GET confirmation -> POST |
| 352/java `GetMappingStateChange` | 2.00/0.33 | 2.00/1.00 | bare verb change this sample - see below |
| 352/javascript `GetRequestStateChange` | 2.00/1.00 | 1.67/1.67 | |
| 352/javascript `FastifyCsrfProtectionMissingRegistration` | 0.00/2.00 | 2.00/1.67 | hook attached |
| 434/javascript `FileFilterDenylistDangerousExtensions` | 0.67/0.00 | 2.00/1.33 | detection out of `fileFilter` |
| 125/cpp `TelemetryClaimedLengthRead` | 0.33/2.00 | **2.00/2.00** | length checked first |
| 79/java `ThymeleafAnnouncementRawHtml` | 1.33/0.00 | **2.00/2.00** | sanitizer used this time |
| 330/go `MathRandSessionId` | 0.00/0.67 | **2.00/2.00** | `token := rand.Text()` |

Plus the two run-12 sharpenings: `502/php/UnserializeCookieData` 2.00/1.67 -> 2.00/2.00 (class
allowed by name) and `79/java/JspScriptletRawExpressionOutput` held at 2.00/2.00.

Two readings matter. `ThymeleafAnnouncementRawHtml` used the OWASP sanitizer this time after quoting
the bullet and declining it in run 12 - so run 12's "model tendency" is stochastic, not a refusal,
and the entry text does move the odds. `352/java/GetMappingStateChange` went the other way: the
confirmation-page pattern it followed in run 12 became a bare `@GetMapping` -> `@DeleteMapping`
change here. Same entry, opposite samples; on Haiku a guidance bullet is a probability, not a switch.

## The contract header at scale: stricter, not more agreed

The 98 cases with `must_preserve` (196 runs) were judged without the contract in run 11 and with it
in run 13:

| Cases | Set | no_harm run 11 -> 13 | splits run 11 -> 13 |
| --- | --- | --- | --- |
| with a contract (196 runs) | A | 1.83 -> **1.56** | 36 -> 41 |
| | B | 1.73 -> 1.72 | |
| without (548 runs) | A | 1.80 -> 1.83 | 89 -> 97 |
| | B | 1.82 -> 1.79 | |

By source the effect sits on `authored-top15-fix-complexity` (85 cases): A no_harm 1.84 -> 1.51 and
fix 1.85 -> 1.69, against B 1.75 -> 1.71 and 1.93 -> 1.85. Arm A's largest drops are all the same
shape - a fix that silently truncates or clamps where the stated contract says reject or report
(`121/c` x3, `787/cpp/VectorReserveThenIndexWrite`, `125`), a `toRealPath()` on a path that does
not exist yet, a call to a function that is never defined. The `cwe/121`, `cwe/787` and `cwe/125`
entries say to detect truncation rather than clamp, and the guided arm mostly does; without the
contract in front of them, judges in run 11 were letting the unguided arm's clamps through as clean.
That is the first time guidance's `no_harm` edge has shown on Haiku, and it appears only once the
contract is scored - which is what `must_preserve` was written to test.

The header did not reduce disagreement: splits on contract cases rose 36 -> 41, and corpus-wide
`fix_quality` splits went 74 -> 98 and `no_harm` 125 -> 138. Run 12's reduction (8 -> 5 on the same
32 write-ups) does not replicate on fresh samples; the header changes what judges score against, not
how often they agree.

## Regressions on untouched slots, checked one by one

Three untouched CWEs lost ground for the guided arm: CWE-90 (n=10) 2.00/2.00 -> 1.67/1.70, CWE-94
(n=22) 1.85/1.55 -> 1.68/1.33, CWE-416 (n=11) 2.00/1.85 -> 1.70/1.79. Reading the write-ups and
notes, four are entry gaps and the rest are slips or rubric-correct 1s:

- **`90/javascript/LdapFilterFromQuery` (2.00/2.00 -> 0.33/0.33; A 0.00/0.00)** - `require('ldapjs-escape')`,
  a package that does not exist (npm 404, confirmed). The entry gave the RFC 4515 escape table but
  named no API. Fixed: `ldapjs` 3.x's own `EqualityFilter` etc. escape on `toString()` (verified
  against the injection payload, ldapjs 3.0.7 / `@ldapjs/filter` 2.1.1), `ldap-escape` 2.0.6 as the
  string fallback with its June 2022 last-publish noted.
- **`94/python/FlaskRenderTemplateStringSSTI` (2.00/2.00 -> 0.67/0.67)** - `from flask import escape`,
  deprecated in Flask 2.3.0 and an `ImportError` on 3.x (confirmed on 3.1.3). Neither `cwe/94/python`
  nor `cwe/79/python` mentioned it. Fixed in `cwe/79/python`: import from `markupsafe`.
- **`94/python/EvalRestrictedBuiltinsFormula` (2.00/2.00 -> 2.00/1.00)** - the AST allowlist omitted
  `ast.Load`, which `ast.walk` yields on every `Name`, so every variable reference was rejected
  (reproduced on CPython 3.13). The entry's allowlist deliberately excluded names and never said what
  to add when a formula needs variables. Fixed.
- **`416/c/DoubleFreeCallbackStructField` (2.00/1.67 -> 0.00/1.00)** - the generation counter was put
  inside the struct being freed, so `ctx->conn->generation` is itself the use-after-free. The entry
  said "store a generation counter in the slot" without saying it must not live in the object.
  Fixed.
- **Slips against text the entry already carries**: `94/java/JexlEngineUnsandboxedEval` invented
  `JexlFeatures.setNewInstance`/`setConstantCreation` where the entry names `newInstance(false)`
  (verified by `javap` on commons-jexl3 3.2.1 and 3.6.0: `allow`/`block` exist in both, `white`/`black`
  are `@Deprecated` in 3.6.0, no `set*` methods - one judge's "`.allow()` does not exist" was wrong);
  `94/csharp/DynamicExpressoCustomFunctionFileRead` deleted the interpreter the entry says to keep
  restricted; `90/java/Case08` declared a variable twice; `94/java/ScriptEngineJavaScriptEval` mistyped
  an `EnumMap`; `416/cpp/EventBusDanglingObserver` changed a signature without updating the caller.
- **Rubric-correct 1s**: the CWE-94 dispatch-table replacements (`GroovyShell`, `IronPython`,
  `CSharpCompilation`) disclose a capability cut and score 1 by design.

Unanimous sub-2 for the guided arm: `fix_quality` 17 -> 19, `no_harm` 28 -> 42 - the no_harm rise is
the contract effect on the hard cases plus the untouched-slot drift.

## What run 13 establishes

1. **The run-11/12 edits generalise from the 47-case subset to the corpus.** Guided arm +0.14/+0.25
   on the edited slots against a flat control; untouched slots drift equally for both arms.
2. **Scoring the stated contract reveals a guided `no_harm` advantage on Haiku that eleven runs never
   showed** - because it was being hidden by silently-truncating unguided fixes scoring clean.
3. **The header raises strictness, not agreement.** Splits went up. Run 12's split reduction was an
   n=32 artefact.
4. **Fresh samples find fresh gaps.** Four entry gaps surfaced in slots no edit touched, three of
   them the CLAUDE.md "removed API / invented API name / concrete syntax" shapes. All four verified
   and fixed after the run; untested.
5. **On Haiku a bullet is a probability.** Two run-12 residuals swapped places this time.

## Limitations

- **Both arms are fresh samples and the panel is fresh**, so run 11 -> 13 differs by sample and
  judges as well as by guidance; arm A is the control for both and is why the edited/untouched
  split, not the totals, carries the claim.
- **Four post-run edits are untested**: `cwe/90/javascript`, `cwe/79/python`, `cwe/94/python`,
  `cwe/416/c`.
- **Operational.** The arm run hit the session limit at 120/744 and was topped up from the on-disk
  done-set (624 fresh runs, identical prompt); judging was interrupted twice (process exit before any
  shard wrote, then 48/57) and completed the same way. 25 nested outputs flattened; one agent wrote a
  byte-identical duplicate to a mangled `E:Github...` path, removed. Corpus and fixtures verified
  unchanged. Judging sharded 19 x 3 as in runs 8-12.
- **`fix_quality` on top-15 fix-complexity fell for both arms** (A 1.85 -> 1.69, B 1.93 -> 1.85) with
  the contract in view; whether judges are reading the contract into `fix_quality` as well as
  `no_harm` is not separable here.
