# Run 17 - complete-file write-ups and the compile gate

Arms, gate and judging complete. The first half of this file is the gate on its own; the judged
tables and the gate-versus-judge comparison follow under **Judged**.

## What changed

Run 17 is a format boundary (HARNESS.md, "What a run is"). Every write-up's `## Fix` now carries
the complete contents of each changed file under a `### File:` heading, and a script
(`scripts/fixgate.py`) applies those files to a scratch copy of the case and runs the Step 0
type check. Nothing else moved: same 372 cases, same rubric, arms on Haiku 4.5
(`claude-haiku-4-5-20251001`), prompts byte-identical between arms except the skill line, the
`cwe/` rule and the output directory. Both arms were sampled fresh; there is no B-pre, because
snippet-format text cannot share a pool with complete-file text, and this A is the frozen control
from run 18 on. The knowledge-base edits since run 16 are two `cwe/79` wording fixes; run 17 is a
baseline and a gate measurement, not a before/after.

| | Arm A (no guidance) | Arm B (skill) |
| --- | --- | --- |
| Write-ups on disk | 372 | 372 |
| Carry at least one `### File:` block | 371 | 369 |
| Files given / differing from the fixture / new | 383 / 379 / 0 | 391 / 387 / 8 |
| Finding's file among those changed | 364 | 362 |
| Fixes touching more than one file | 7 | 15 |
| Total size | 1.07 MB | 1.43 MB |

Run 16's B-post was 1.19 MB in snippet form, so the complete-file format costs little: the old
before/after snippets were most of the file anyway. Format compliance was 740 of 744. The four
`NO_FILES` write-ups are `A/94/java/ScriptEngineJavaScriptEval` and
`B/77/java/FtpRawSocketFilenameInjection` (prose fixes with no file), `B/89/java/Case14`
("no fix required") and `B/434/python/S3ObjectContentTypeMetadataTrust` (a one-paragraph plan).
None was re-run; they go to the judges as written.

Launch: a 42-case CWE-89 pilot (84 agents, 3.3M subagent tokens, 5 minutes) to check format
compliance, then the other 330 cases (660 agents, 27.3M tokens, 43 minutes; 15 agents lost to
the session limit and four returned without writing a file), then a 12-agent top-up (0.5M).
No fixture was modified. Agents left scratch files in the repository root and one compiled
`.class` under `stubs/java/shared`, all removed.

## The gate

Two passes. The first ran against the superset manifests as built from the fixtures and failed
29 arm-A and 39 arm-B write-ups. Reading the notes, nearly half of A's and half of B's were a
library the fix brings in that no fixture uses - the guided arm follows the entries'
recommendations, so this lands on B: Tika, the OWASP Java Encoder and HTML Sanitizer,
commons-lang3, commons-text, jakarta.mail and javax.mail, `golang.org/x/crypto/bcrypt`,
StackExchange.Redis, EnyimMemcachedCore, Flask-WTF, joblib, RestrictedPython, and nine npm
packages (`bcrypt`, `csurf`, `@fastify/csrf-protection`, `mathjs`, `expr-eval`, `acorn`,
`isolated-vm`, `sharp`, `fast-xml-parser`). Every one of those is a real published package under
the name the write-up used, so each was added to its language's superset (HARNESS.md Step 3,
"Triage the first pass") and the gate re-run. A name that resolves nowhere stayed a failure.
The fixtures still pass the extended supersets.

Second pass, per write-up:

| Arm | Language | OK | FAIL | UNCHECKED | NO_FILES | n |
| --- | --- | --- | --- | --- | --- | --- |
| A | c | 22 | 0 | 0 | 0 | 22 |
| A | cpp | 18 | 1 | 0 | 0 | 19 |
| A | csharp | 48 | 2 | 4 | 0 | 54 |
| A | go | 37 | 6 | 0 | 0 | 43 |
| A | java | 79 | 4 | 2 | 1 | 86 |
| A | javascript | 45 | 0 | 3 | 0 | 48 |
| A | perl | 3 | 1 | 0 | 0 | 4 |
| A | php | 41 | 2 | 1 | 0 | 44 |
| A | python | 52 | 0 | 0 | 0 | 52 |
| **A** | **all** | **345** | **16** | **10** | **1** | **372** |
| B | c | 22 | 0 | 0 | 0 | 22 |
| B | cpp | 18 | 1 | 0 | 0 | 19 |
| B | csharp | 44 | 6 | 4 | 0 | 54 |
| B | go | 43 | 0 | 0 | 0 | 43 |
| B | java | 73 | 10 | 1 | 2 | 86 |
| B | javascript | 44 | 1 | 3 | 0 | 48 |
| B | perl | 4 | 0 | 0 | 0 | 4 |
| B | php | 43 | 0 | 1 | 0 | 44 |
| B | python | 50 | 1 | 0 | 1 | 52 |
| **B** | **all** | **341** | **19** | **9** | **3** | **372** |

`UNCHECKED` is the nine fixtures Step 0 cannot check (Web Forms, JSP, Blazor, JSX, `libxmljs`)
plus write-ups whose only changed file is a template (a Razor view, a Blade view, a Thymeleaf
template) or a native npm package that installs without its binding (`bcrypt`, `isolated-vm`).
`evals/runs-v17/gate.json` holds every row with its note and file list.

### What the failures are

By kind (`scripts/gatekinds.py`, added after the run and applied to `gate.json`):

| Kind | A | B |
| --- | --- | --- |
| missing-import (a real class, not imported) | 3 | 10 |
| unresolved-name (nothing defines it) | 1 | 3 |
| unresolved-member (a method or export the type lacks) | 5 | 2 |
| signature (real API, wrong arguments or types) | 2 | 3 |
| syntax | 0 | 1 |
| unused import or variable (Go) | 4 | 0 |
| runtime (an invalid regex the checker rejects) | 1 | 0 |

Half of the guided arm's failures are a missing import of a class that exists; the unguided
arm's are spread across invented members and Go's unused declarations.

Every remaining `FAIL` note was read. One is the checker, not the fix:
`B/326/python/AesEcbModeEncrypt` calls `AESGCM.generate_key(bit_length=256)`, which mypy rejects
under cryptography 43.0.3's type stubs and which runs (reproduced). Counting that as a pass, the
compile-failure rate is **16 of 372 for A (4.3%) and 18 of 372 for B (4.8%)**, and the shapes are
the ones runs 13-16's judges kept naming, now found by a compiler at no token cost:

- **Invented names** - A: `mysqli_bind_param()` (the function is `mysqli_stmt_bind_param()`),
  `DatabaseHelper.getConnection()` (the helper has `getSqlConnection()`),
  `SyntaxTree.GetCompilationUnitSyntax()` (`GetCompilationUnitRoot()`), `gob.Decoder.SetTypeFilter`,
  a `Document` entity that exists nowhere, `CGI::Util`'s `html_escape` (the module exports no such
  name). B: `ResponseEntityBuilder`, `expr-eval`'s `evaluate` export (the module exports `Parser`),
  `using EnyimMemcached;` for a package whose namespace is `Enyim.Caching`.
- **Wrong package for a real class** - B, four times, and all four trace to the knowledge base:
  three write-ups imported `org.apache.commons.jexl3.JexlSandbox` (it is in
  `org.apache.commons.jexl3.introspection`) and one imported `org.owasp.html.Encode` (it is
  `org.owasp.encoder.Encode`; `org.owasp.html` is the sanitizer, which `cwe/79/java` had just
  been edited to name). `cwe/94/java` and `cwe/79/java` named the classes without their packages;
  both now do. This is the first entry defect a compiler found rather than a judge.
- **Missing import or `using`** - A: `AccessDeniedException`, `System.Runtime.Loader`. B:
  `System.Data` (twice), `Microsoft.AspNetCore.Antiforgery`, `java.awt.image.BufferedImage`,
  `java.io.File`, `jakarta.mail.internet.AddressException` (a `jakarta.mail.*` import does not
  reach the `internet` subpackage), `<stdexcept>` for `std::out_of_range`.
- **Wrong signature or type** - B: `Stream.ReadAtLeastAsync` with the cancellation token in the
  `bool` slot, a Nimbus `JWSAlgorithm` passed where a `String` is required. A: a `[]byte` passed to
  `image.DecodeConfig`, which takes an `io.Reader`; a `std::unique_ptr` moved into a lambda stored
  in a `std::function`, which must be copyable.
- **An API from a newer version than the fixture's, without saying so** - A: jjwt 0.12's
  `parseSignedClaims()` against the 0.11.5 the fixture uses. B: `SpaCsrfTokenRequestHandler`,
  claimed "available in Spring Security 6.1+" on a `javax`-era fixture; the write-up neither
  states the upgrade as a step nor supplies the class.
- **Go's strictness** - A: three unused variables, one unused import. B: none. Go is the one
  language where the guided arm is cleaner by a margin (0 against 6), and it is the language
  whose compiler rejects the most ordinary carelessness.
- **Two genuine PHP bugs** - A: a `/` inside a `/.../` character class ("Unknown modifier"), and a
  syntax error in a C# escape table.

The gate does not see everything a judge sees: a fix that compiles and does nothing, a fix that
compiles and breaks the contract, or a fix in a template. It sees the slip bucket exactly, and it
sees it in twenty minutes of machine time.

## Judged

Three `cwe-judge` agents (Sonnet 5, `claude-sonnet-5`) per bundle segment, 50 segments of the
744-item pool, rubric with the disclosed-narrowing pin (HARNESS.md Step 5). The gate result was
withheld from the judges. 150 of 150 score files valid on the first launch; 11.9M subagent
tokens, 59 minutes, about 16k tokens per scored write-up.

| Set | n | fix_quality | no_harm | clean (2.00/2.00) | fq splits | nh splits |
| --- | --- | --- | --- | --- | --- | --- |
| A (no guidance) | 372 | 1.80 | 1.76 | 256 | 42 | 51 |
| B (skill) | 372 | 1.91 | 1.74 | 263 | 27 | 64 |

Paired by case: `fix_quality` B above A on 64 cases, A above B on 22, tied on 286. `no_harm`
A above B on 73, B above A on 59, tied on 240. These numbers sit on the run-17 scale (fresh
samples, complete-file format, compiling panel with the pin) and are not comparable to runs
11-16 by value; the arm gap is the comparison.

By language (fq / nh, clean):

| Language | A | B |
| --- | --- | --- |
| c | 1.92 / 1.79, 18 of 22 | 1.97 / 1.91, 18 |
| cpp | 1.88 / 1.84, 16 of 19 | 2.00 / 1.91, 18 |
| csharp | 1.73 / 1.68, 34 of 54 | 1.93 / 1.72, 35 |
| go | 1.79 / 1.67, 28 of 43 | 1.93 / 1.78, 34 |
| java | 1.78 / 1.80, 56 of 86 | 1.83 / 1.63, 54 |
| javascript | 1.79 / 1.86, 35 of 48 | 1.89 / 1.69, 31 |
| perl | 1.50 / 1.50, 3 of 4 | 2.00 / 2.00, 4 |
| php | 1.92 / 1.80, 35 of 44 | 1.98 / 1.84, 34 |
| python | 1.79 / 1.72, 31 of 52 | 1.92 / 1.74, 35 |

By source: guidance's `fix_quality` edge is largest where the cases are hardest -
`authored-top15-fix-complexity` 1.73 to 1.91 and `authored-from-docs-pitfall` 1.67 to 1.92 -
and absent on `owasp-benchmark` (1.98 both). By CWE the widest gap is CWE-94 (1.38 to 1.83 on
22 cases); CWE-287 moves 1.70 to 1.94.

### Where the guided arm loses `no_harm`

B's `no_harm` is level with A overall and behind it in Java (1.63 against 1.80) and JavaScript
(1.69 against 1.86). Reading every write-up where all three judges scored below 2 (A 43, B 51):

- **Narrowing the entries prescribe.** Ten unanimous B misses are an allowlist regex added on
  top of the API fix, scored 1 under the pin because no stated contract calls for it -
  `^[a-zA-Z0-9._-]+$` on an LDAP username beside `escape_filter_chars()`, on a report name beside
  `execFile()`, on a filename beside `FTPClient.retrieveFile()`. The arm did what it was told:
  `cwe/90/INDEX.md` says "apply strict allowlist validation for filter components",
  `cwe/90/csharp` gives that exact regex, `cwe/78/INDEX.md` adds allowlists "as a secondary
  defence layer". The rubric and the knowledge base disagree here, and the run cannot settle
  which is right: the pin treats an allowlist that could reject a legitimate value as harm unless
  the contract asks for it, the entries treat it as defence in depth. That is a doctrine decision
  for the entries (CWE-77, 78, 90 families), not something to fix in one file.
- **Silent behaviour change while rewriting the whole file.** Fourteen unanimous B misses and
  nine A misses are a rewrite that changed something beside the sink: a `ping` diagnostic
  replaced by a TCP-connect probe, a return value dropped, a request context no longer honoured,
  and one `main()` rewritten without its `/login` handler (`B/117/go`, `no_harm` 0.00). The
  complete-file format makes this easier to do and easier to see; whether it made it more common
  than the snippet format cannot be measured across the boundary.
- The rest are the usual gray zone (disclosed changes the judges weighed differently, 27 B and
  23 A), and B's `no_harm` splits (64 against 51) say the pin did not remove the zone.

### The gate against the judges

| Gate status | n | mean fq | mean nh | all three judges gave fq 2 | at least one judge asserts a compile or name error |
| --- | --- | --- | --- | --- | --- |
| OK | 686 | 1.90 | 1.80 | 609 | 8 |
| FAIL | 35 | 1.10 | 0.94 | 11 | 21 |
| UNCHECKED | 19 | 1.91 | 1.70 | 15 | 0 |
| NO_FILES | 4 | 1.25 | 1.33 | 2 | 0 |

The gate and the panel agree on the direction - a gate `FAIL` costs 0.8 on both criteria - and
disagree on eleven write-ups the panel passed unanimously at 2.00: ten real compile errors
(`DatabaseHelper.getConnection()`, `SqlDbType` without `using System.Data`, `using
EnyimMemcached`, `IAntiforgery` without its `using`, `std::out_of_range` without `<stdexcept>`,
an unused Go import, a `[]byte` handed to `image.DecodeConfig`, a PHP regex with an unescaped
`/`, `JexlSandbox` from the wrong package, `ReadAtLeastAsync` with the token in the `bool` slot)
and the one checker false positive. The other way round, no gate-`OK` write-up drew a compile
claim from two judges that held up (the two matches are a regex artefact on "rejects undefined
names"). So the judges' own compiling, which run 16 introduced and which is most of their Bash
turns, catches a subset of what the gate catches and nothing the gate misses. From run 18 the
blinded header carries the gate line (`Build: OK` / `Build: FAIL - <first error>` /
`Build: unchecked`), the judge prompt tells the panel to take it as settled and not compile, and
the saving is measured against this run's 16k tokens per write-up.

## What this establishes

- The format works on Haiku: 740 of 744 write-ups carry complete files, and the gate reads them
  without hand-work.
- Roughly one guided fix in twenty and one unguided fix in twenty does not build. The guided arm
  is not cleaner on this axis; it fails differently - by reaching for a library or class the
  entry names (and, four times, naming it imprecisely) - where the unguided arm invents helper
  methods and leaves Go variables unused.
- A superset built from the fixtures alone is the wrong environment for gating fixes. The right
  one is the fixtures' surface plus every library the knowledge base recommends; run 17's first
  pass is the measurement of that gap (13 arm-A and 20 arm-B failures that vanished when the
  libraries were added), and the manifests now carry them.
- Two entry defects (`JexlSandbox` and `Encode` packages) were found by the compiler and fixed;
  neither had surfaced in sixteen judged runs.
- Judged, guidance lifts `fix_quality` by 0.11 on 372 cases (B ahead on 64 cases, behind on 22)
  and leaves `no_harm` level, with the guided arm's losses concentrated in allowlists the entries
  prescribe and the rubric penalises, and in whole-file rewrites that change something beside the
  sink.
- The gate strictly dominates the judges' own compiling on the slip bucket; the judges can stop.

## Limitations

- The gate reflects one environment per language. A fix that needs a dependency upgrade fails
  here whether or not the write-up says so; the two cases of that shape are listed above.
- Ten arm-A and nine arm-B write-ups are unchecked (framework-hosted files and native bindings).
- One sample per arm on one model, and the session limit interrupted the launch; the 12 top-up
  agents ran under the identical prompt.
- The narrowing-versus-defence-in-depth question is a finding about the rubric and the entries
  together; this run measured it and did not resolve it.
- The "asserts a compile or name error" column is a regular expression over judge notes and
  undercounts phrasing it does not know.

## Cost

Arms: 756 Haiku agents, 31.1M subagent tokens (about 41k per write-up), 51 minutes of wall clock
across three launches. Gate: about 20 minutes of machine time per pass, no tokens. Judges: 150
Sonnet agents, 11.9M subagent tokens (about 16k per scored write-up), 59 minutes.
