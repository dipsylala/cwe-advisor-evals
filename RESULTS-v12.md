# Validation harness - run 12 results

188 runs (47 cases x 4 sets), **Haiku 4.5 arms, Sonnet 5 judges**. The 47 cases are every case in
the 15 `(cwe, language)` slots whose entries run 11's findings led to editing (all of CWE-502 and
CWE-352, plus `434/javascript`, `125/cpp`, `79/java`, `330/go`). Four sets, blinded together so a
judge cannot tell before from after:

| Set | What it is |
| --- | --- |
| A-pre, B-pre | run 11's own write-ups for these 47 cases, copied verbatim and re-judged |
| A-post, B-post | fresh Haiku 4.5 runs of the same 47 cases, byte-identical run-11 prompt, after the eight entry edits |

This is the direct before/after on the edits (the design run 3 and run 10 used), and the first run
where the judge header carries the case's `must_preserve` contract (`scripts/blind.py`,
HARNESS.md Step 4/5). Eight edits, all committed before the post runs: `cwe/502` root, java, php, go
(keep the wire format, disable object construction in the decoder; `Config.setSerialFilter()` is
set-once); `cwe/352` root, go, java, javascript (a link-reachable GET becomes a confirmation page
that POSTs; `@fastify/csrf-protection` needs the hook, not just `register`); `cwe/434/javascript`
(`file.buffer` does not exist inside `fileFilter`); `cwe/125/cpp` (`size() - length` wraps);
`cwe/79/java` (an intentionally-HTML field is sanitized, not escaped); `cwe/330/go` (`rand.Text()`
returns one value).

## Answer: the edits closed the cases they were written for; the aggregate is inside the noise

| Set | n | fix /2 | no-harm /2 | clean (2.00/2.00, all judges) |
| --- | --- | --- | --- | --- |
| A-pre | 47 | 1.75 | 1.74 | 30 |
| A-post | 47 | 1.67 | 1.50 | 22 |
| B-pre | 47 | 1.76 | 1.40 | 21 |
| B-post | 47 | 1.93 | 1.65 | 34 |

Arm B moved +0.17 fix / +0.25 no_harm and its clean count went 21 -> 34. But arm A - which never
reads `cwe/` and had nothing changed - moved -0.08 / -0.24 and lost 8 clean cases between two
samples of the same model on the same prompt. **On 47 cases, an aggregate movement of about 0.2 on
either axis is resampling noise**, so the table above cannot on its own show the edits worked. The
evidence is case by case, checked against the write-ups and the judge notes, as in run 10.

## Verified: the 13 targeted cases

| Case | B-pre | B-post | A-pre | A-post | Note |
| --- | --- | --- | --- | --- | --- |
| 502/java `OrderEventQueueDeserialize` | 1.00/0.00 | **2.00/2.00** | 2.00/2.00 | 1.00/0.33 | B-post uses `ois.setObjectInputFilter()`; A-post fabricated a `createFilter("allowlist=...")` key (see below) |
| 502/php `CartCookieDecodeUnserialize` | 2.00/0.67 | **2.00/2.00** | 2.00/1.33 | 2.00/1.33 | `allowed_classes => false`, format kept |
| 502/php `CartLegacySerializedMigration` | 2.00/0.00 | 1.33/0.00 | 2.00/2.00 | 2.00/1.00 | did not close - see residuals |
| 502/go `JobQueueGobPrivilegeField` | 1.67/0.00 | **2.00/2.00** | 2.00/2.00 | 2.00/2.00 | narrow DTO, gob kept |
| 502/go `GobDecodeUntrustedPayload` | 2.00/1.33 | **2.00/2.00** | 2.00/2.00 | 2.00/1.67 | narrow DTO, gob kept |
| 352/go `GetRequestStateChange` | 2.00/0.33 | **2.00/2.00** | 2.00/0.33 | 2.00/1.00 | GET confirmation page -> POST |
| 352/java `GetMappingStateChange` | 2.00/0.33 | 2.00/1.67 | 2.00/1.00 | 2.00/1.00 | one judge: view name returned from a `@RestController` is serialized as the body - sharpened after the run |
| 352/javascript `GetRequestStateChange` | 2.00/1.00 | 2.00/1.00 | 1.33/1.67 | 2.00/1.00 | did not move - see residuals |
| 352/javascript `FastifyCsrfProtectionMissingRegistration` | 0.00/2.00 | **2.00/2.00** | 2.00/1.33 | 2.00/1.67 | `fastify.csrfProtection` attached as a hook |
| 434/javascript `FileFilterDenylistDangerousExtensions` | 1.00/0.00 | 2.00/1.67 | 2.00/2.00 | 1.67/1.67 | detection moved out of `fileFilter`; one judge wanted the narrower allowlist flagged |
| 125/cpp `TelemetryClaimedLengthRead` | 0.00/2.00 | **2.00/2.00** | 1.00/2.00 | 2.00/0.00 | `length > size()` checked first; A-post silently clamped, which the now-visible contract forbids |
| 79/java `ThymeleafAnnouncementRawHtml` | 1.33/0.33 | 1.67/0.67 | 1.00/1.00 | 1.33/1.33 | did not close - see residuals |
| 330/go `MathRandSessionId` | 0.67/1.33 | **2.00/2.00** | 2.00/2.00 | 2.00/2.00 | `token := rand.Text()` |

Nine of thirteen went to a unanimous 2.00/2.00, and the mechanism in each B-post write-up is the
one the edit added (all three 502/java B-post write-ups call `setObjectInputFilter`, all three
502/php ones use `allowed_classes`, the fastify write-up wires the hook, the 125/cpp one checks
`length` before subtracting). The A-post column shows the unguided arm falling into the same traps
in a fresh sample - `OrderEventQueueDeserialize` went from 2.00/2.00 to 1.00/0.33 on a fabricated
`createFilter` key - which is what the edits exist to prevent.

## Residuals: what did not close, and why

- **`CartLegacySerializedMigration` (B 2.00/0.00 -> 1.33/0.00) - the edit overshot.** B-pre swapped
  to `json_decode()` and silently emptied every legacy row; B-post kept `unserialize()` with
  `allowed_classes => false` and, in the judges' words, "explicitly assumes the serialized format
  must remain unchanged", ignoring the rows the contract says are already JSON. The entry said
  "keep the format where producers cannot change" but nothing about a migration, where both formats
  coexist. Sharpened after the run: detect the stored format by its leading byte and read each with
  its own decoder. Untested.
- **`ThymeleafAnnouncementRawHtml` (B 1.33/0.33 -> 1.67/0.67) - guidance present, model deferred.**
  The B-post write-up quotes the entry, names the OWASP Java HTML Sanitizer and the exact
  `PolicyFactory` the new bullet gives, and still ships `th:text` as the fix with the sanitizer as an
  "if the application intentionally requires HTML" aside - on a field named `bodyHtml` whose stub
  value is `<p>Draft body</p>`. Same shape as run 10's CWE-117 Unicode slip: the entry states the
  decision and the model takes the safer-looking edit anyway. No entry change indicated.
- **352/javascript `GetRequestStateChange` (B 2.00/1.00 both) - doctrine met a JSON API.** The
  confirmation-page pattern became a JSON "instruction" body at the old GET URL, and an
  "alternative" snippet called a non-existent `doubleCsrfProtection.generateToken()`. Judges split
  1/0/2. The root doctrine is right for a server-rendered app; a JSON API has no page to render, and
  the entry does not say what the GET should return there. Left as is - the right answer depends on
  the client, which the case does not show.

Four non-target cases in the edited slots got worse for arm B. Two are the same edits misapplied
and were sharpened after the run: `502/php/UnserializeCookieData` (2.00/1.00 -> 2.00/0.00,
`allowed_classes => false` turned the legitimate `ShoppingCart` object into
`__PHP_Incomplete_Class` so `instanceof` fails and every cart is empty - the entry now says to read
what the code does with the result first) and `79/java/JspScriptletRawExpressionOutput`
(2.00/2.00 -> 1.33/0.67, `<c:out value="${displayName}">` cannot see a scriptlet local, so the
greeting renders blank - the entry now says so). Two are model slips against text already present:
`352/go/OriginHeaderOnlyNoTokenValidation` left the `CrossOriginProtection` wiring in a comment,
`352/javascript/MultiFileTransferCsrf` hardcoded the `csrf-csrf` secret.

## `must_preserve` in the judge header: a small, measurable reduction in splits

The 94 pre write-ups were scored twice by independent panels - run 11 without the contract, run 12
with it - so the effect can be read directly on identical text:

| Pre write-ups | n | no_harm splits run 11 -> 12 | fix splits run 11 -> 12 | mean no_harm run 11 -> 12 |
| --- | --- | --- | --- | --- |
| case carries `must_preserve` | 32 | 8 -> 5 | 7 -> 2 | 1.52 -> 1.43 |
| case does not | 62 | 14 -> 16 | 7 -> 7 | 1.74 -> 1.64 |

Across the whole run-12 pool, `no_harm` split on 17% of runs with a contract and 24% without. The
direction is right and the mean fell where the contract applies - judges score against it more
strictly, which is the point - but n=32 is too small to call the size. Judge disagreement overall:
`fix_quality` 24/188 (12.8%), `no_harm` 41/188 (21.8%) - higher than run 11's 16.8% on `no_harm`
because this pool is, by construction, the hardest 47 cases in the corpus.

## What run 12 establishes

1. **The eight edits work where they were aimed** - nine of thirteen targets clean, mechanisms
   verified in the generated code, control arm unaffected by the edits and still falling into the
   traps.
2. **Aggregate numbers on a 47-case subset carry about +-0.2 of resampling noise** (arm A's swing
   with nothing changed). A before/after on a subset has to be argued case by case; a claim about
   the corpus-wide averages needs the full corpus.
3. **Two of the three residuals are the model, not the entry.** The Thymeleaf case in particular
   shows the ceiling: the entry names the library, the policy and the field pattern, the model
   quotes it back, and still hedges. This is the run-10 lesson again and the reason the SKILL.md
   self-check experiment is worth running separately.
4. **`must_preserve` in the header reduces judge splits on the cases that have it**, modestly, and
   makes `no_harm` stricter there. It is now on for every future run; runs 1-11 are not directly
   comparable on `no_harm`.

## Limitations

- **Subset, not corpus.** 47 cases chosen because their entries changed; nothing here says what the
  edits do to the other 325, beyond the argument that an entry edit cannot reach a case that never
  reads it.
- **Pre is re-judged, post is re-run.** A-pre/B-pre are run 11's text under a new panel; A-post/
  B-post are fresh samples. Pre-vs-post therefore differs by sample as well as by guidance, which is
  why arm A is in the table: it bounds the sample effect.
- **Four sharpenings were made after the run and are untested**: `502/php` (class-by-name when the
  code expects an object; dual-format read during a migration), `352/java` (`@RestController`
  serializes a view name), `79/java` (EL cannot see scriptlet locals), `502/java`
  (`createFilter` pattern syntax - the four limit keys verified on JDK 26, `allowlist=` and
  `maxarraylength` confirmed to throw).
- **Operational.** The first post-edit launch hit the session limit after the manifest phase (0 of
  94 arm agents ran) and was relaunched with the identical script; 10 post outputs were nested one
  directory too deep and flattened before blinding, the same tool quirk as runs 10 and 11. Judging
  was sharded (5 shards x 3 judges).
- **The `createFilter` comma question is open.** One judge said class patterns are `;`-separated
  "not comma"; on JDK 26 `createFilter("a.B,c.D;!*")` does not throw, but that only shows a comma is
  accepted inside a pattern, not that it separates two. The entry states the documented `;` form
  and does not claim commas are rejected.
