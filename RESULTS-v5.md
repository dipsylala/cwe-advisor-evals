# Validation harness - run 5 results

158 runs (79 cases x 2 arms) on the `authored` corpus - the breadth and per-language-depth cases
that runs 1-4 never touched, all `true_positive`, all chain depth 1, spanning 14 CWEs (22, 78, 79,
89, 90, 117, 209, 326, 330, 338, 347, 434, 502, 611, 614) across seven languages. Scored blind by
three judges who each scored all 158. Scores are the mean across the three. Executed from
HARNESS.md's arm A/B prompts and judge rubric verbatim, orchestrated as a workflow: 158 remediation
agents, a fixture-integrity check, blinding, three independent judges, and `analyse.py`.

The question: this is the corpus README.md flagged as never run - does the skill help on the
ordinary, undramatic case (no planted trap, no multi-file chain), across this many CWEs and
languages at once?

## Answer: fix_quality is saturated again, no_harm shows a small, real gap

| Set | n | fix /2 | no-harm /2 |
|---|---|---|---|
| A - no guidance | 79 | 2.00 | 1.97 |
| B - skill | 79 | 2.00 | 2.00 |

Same headline as every run before it: a capable model does not need help recognising or closing a
textbook single-file vulnerability. 156 of 158 runs scored a full 2/2 on `fix_quality`; the two
exceptions are one per arm (below), not a systematic gap.

`no_harm` moves in the direction runs 2-3 found: guided is cleaner. Judges disagreed on `no_harm` in
5 of 158 runs and on `fix_quality` in 2 of 158 - both far below run 4's 45% disagreement rate,
because these cases carry no `must_preserve` contract to argue about; judges are scoring plainly
observable behaviour change.

## Where the points were lost

| run | case | CWE | lang | arm | fix | no-harm | why |
|---|---|---|---|---|---|---|---|
| R195 | MathRandSessionId | 330 | go | A | 2.00 | 1.33 | Fix drops the username from the session-ID value with no server-side session store to compensate, breaking the endpoint's only way to identify the session's user. Sibling `R122` (arm B, same case) kept the username-token format. |
| R117 | AvatarUploadNoTypeCheck | 434 | go | A | 2.00 | 1.33 | Server-generated random filename is correct, but it is never returned to the client, and the unchanged `http.FileServer` route means legitimate avatar retrieval silently breaks. |
| R172 | AvatarUploadNoTypeCheck | 434 | go | B | 2.00 | 1.67 | The same defect as R117, independently, in the guided arm. |
| R121 | UnserializeCookieData | 502 | php | A | 2.00 | 1.67 | Switches wire format from `unserialize()` to `json_decode()`; correctly flags that the cookie-writing side must be updated to match, but that side is out of scope for this fix, so previously-issued cookies are silently invalidated. |
| R103 | ExpressCookieNoSecureFlag | 614 | javascript | A | 2.00 | 1.67 | `secure: true` closes the finding cleanly but the write-up also adds an unrelated 400 "Missing token" guard clause not present in the original. |
| R158 | MultipartUploadNoValidation | 434 | java | A | 1.67 | 2.00 | Type gate relies only on the client-declared content-type and filename extension, both spoofable, with no content-byte verification - two of three judges called this the wrong shape for a dangerous-upload sink despite the extension allowlist and off-webroot storage. |
| R173 | MtRandResetToken | 338 | php | B | 1.67 | 2.00 | `random_int()` correctly replaces the weak, client-seeded `mt_rand()`, but keeps the original 1,000,000-value range, leaving the reset token brute-forceable within its lifetime. |

## The AvatarUploadNoTypeCheck defect is case-level, not arm-level

R117 (control) and R172 (guided) hit the identical failure independently: both regenerate the
upload's filename for security (content-sniffing plus a random name, entirely correct for CWE-434),
and both forget that the file is served back through an unchanged route that still expects the
original name. Neither arm needed the skill to make this mistake, and the skill did not prevent it
either - `cwe/434/go/INDEX.md`'s guidance covers validating what gets stored, not what a
renamed-on-write file needs on the read path for the caller to still find it. That is a real gap
worth closing in the entry, distinct from the "no_harm" scoring question: an entry can teach a
correct write-side fix and still ship a broken read side if it never mentions the coupling.

## What run 5 establishes

1. **`fix_quality` is saturated at this scope too.** 79 more true-positive, single-file, single-CWE
   cases across 14 CWEs and 7 languages, and the model closes the reported vector correctly in 156
   of 158. This is now five runs in a row where fix_quality does not discriminate; further cases
   built the same way (confirmed true positive, no deliberate trap) will not either.
2. **`no_harm` favours the guided arm, consistent with run 3, on a genuinely low-noise measurement.**
   A=1.97 vs B=2.00 is a small gap, but the disagreement rate underneath it (5/158, 2/158) is far
   lower than run 4's, because these cases have no contested `must_preserve` contract - the
   deductions are for concretely observable, undisputed behaviour changes (a silently broken
   retrieval path, a silently invalidated cookie format, a scope-creep guard clause).
3. **One new, reproducible entry gap.** `cwe/434/go` (and by the same shape, `cwe/434` generally)
   does not warn that renaming an uploaded file for safety requires the read path to learn the new
   name - both arms independently shipped a fix that breaks retrieval.
4. **The per-run detail is a starting inventory for a smaller `authored-from-docs-pitfall` batch.**
   Every deficiency above is a concrete, judge-explained failure mode (dropped session data, broken
   retrieval, invalidated cookie format, unpreserved brute-force resistance) that could seed a
   deliberately-planted case the way run 4's batch was seeded from `docs/` pitfalls.

## Limitations

- **n = 1 per (CWE, language) cell.** Every per-CWE and per-language row in the full table is a
  single run; the aggregate numbers are a corpus-wide summary, not a per-cell-supported claim.
- **Cases are `authored` here**, not externally sourced like `owasp-benchmark` or `juliet` - their
  labels are an authoring claim, weaker ground truth than the two external sources, though none of
  the deficiencies above turn on the label being wrong (all seven are `no_harm`/`fix_quality`
  judgments on an agreed-real finding).
- **Nothing was compiled or executed.** Every deduction above (broken retrieval, invalidated cookie
  format, brute-forceable range) was reasoned from reading the code, not from running it.
- **`source_identified` and `verdict_correct` were not scored.** Every case here is a confirmed true
  positive with no exploitability judgment call for the arm to make, per HARNESS.md's current scope.
- **All cases are chain depth 1.** This run does not touch multi-file tracing, which runs 1-3
  already found saturated up to five files.
