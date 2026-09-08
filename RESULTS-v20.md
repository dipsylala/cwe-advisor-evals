# Run 20 - Sonnet 5 on both arms, judged by Fable

A full run (HARNESS.md, "What a run is") and a new judge scale: fresh unguided (A) and guided (B)
samples from Sonnet 5 (`claude-sonnet-5`) on all 372 cases, the complete-file write-up format,
the compile gate, and three `cwe-judge` agents per segment on Fable (`claude-fable-5-1`) instead
of Sonnet 5. Two questions:

- Does guidance still help a stronger arm, or only stop hurting it? Runs 17-19 tuned the entries
  against Haiku's failure modes; on earlier corpora Sonnet saturated `fix_quality` regardless of
  guidance.
- What does a judge that is not the arm's own model make of the same rubric? Sonnet judging
  Sonnet carried a self-preference risk, so both this run and run 21 (a fresh Haiku pair) are
  judged by Fable. The two runs share a scale with each other and with nothing before them.

Same prompts as runs 17-19, byte-identical between arms except the skill line, the `cwe/` rule
and the output directory. The judge prompt gained one paragraph: a reproduction payload must be
inert (a marker file, never a launched program), and the Build line is not to be second-guessed
by compiling. Sonnet's write-ups run 30-45% larger than Haiku's (median 3.1 KB unguided and
4.5 KB guided against 2.4 KB and 3.1 KB on the CWE-89 pilot) and still fit the 80 KB segment.

## Gate

| Arm | OK | FAIL | UNCHECKED | NO_FILES | Kinds of FAIL |
| --- | --- | --- | --- | --- | --- |
| A (unguided) | 353 | 7 | 9 | 3 | missing-package 2, other 2, signature 1, unresolved-member 1, unused 1 |
| B (guided) | 354 | 3 | 9 | 6 | unresolved-member 2, other 1 |

The lowest failure counts of any run: Haiku's fresh pair in run 17 was 16 and 18. Sonnet's slips
have a different shape from Haiku's - two of the unguided arm's seven are a duplicate class
declaration in a multi-file rewrite (`JwtBearerSetup`, `IChatMessageStore` re-declared beside
the fixture's own) - and two are the same invented members Haiku produces on the same cases
(`ChatMessage.UserId`, `Order.getOwnerUsername()`), plus `setRootObject()` on the simple SpEL
context in the unguided arm, which every model has now invented at least once.

Seven first-pass rows were package gaps under the triage rule and four resolved to `OK` once
the superset carried the real package the fix named: `expr-eval-fork` and `@angular/core`
(npm), `org.graalvm.polyglot:polyglot` and `jakarta.servlet-api` (Maven). Three stayed failed
for reasons the arm owns: `jdk.nashorn.api.scripting` resolves nowhere on a JDK 17+ classpath
(the standalone Nashorn uses `org.openjdk.nashorn`), `org.springframework.security.authentication.www`
is not a Spring package, and the guided CSRF handler was written against the jakarta generation
of Spring Security on a fixture whose superset is the javax line - the fixture gives no signal
either way, and both arms guessed jakarta.

`NO_FILES` is a write-up that changed nothing. Nine of them, three unguided and six guided, and
all but two declare the confirmed finding not exploitable (the Juliet `Case13`/`Case14`/`Case15`
shapes where the tainted value is a literal, a PHP `$$cmd()` dispatch, a C++ erase loop). Sonnet
declines findings where Haiku patches them; the rubric treats every finding as confirmed, so the
judges score those 0 on `fix_quality` except where they agreed the sink was already closed.

## Judged

| Arm | fix_quality | no_harm | clean | no_harm < 2 | judge splits |
| --- | --- | --- | --- | --- | --- |
| A (unguided) | 1.92 | 1.70 | 241 | 125 | 42 |
| B (guided) | 1.94 | 1.76 | 257 | 106 | 42 |

Paired per case: `fix_quality` guided ahead on 17, behind on 12, tied on 343; `no_harm` guided
ahead on 80, behind on 48, tied on 244. The Build line was obeyed 10 of 10.

**Fix quality is saturated, as it was on earlier corpora.** Both arms sit at 1.92-1.94 with 343
of 372 cases tied, and the 29 that differ are mostly the no-fix verdicts and the build failures.
Guidance cannot show up on this axis for Sonnet because there is nowhere for it to go.

**Guidance shows up on `no_harm` and on the gate.** 1.70 to 1.76 overall, 80 cases ahead against
48 behind, clean write-ups 241 to 257, build failures 7 to 3. The gain is concentrated where the
entries carry API-shape facts a strong model still gets wrong on its own: CWE-89 (1.71 to 1.89 -
the Sequelize `bind` placeholders, the mysql2 `execute()` distinction), CWE-352 (1.51 to 1.71),
CWE-79 (1.88 to 1.99), CWE-78 (1.25 to 1.38), CWE-94 (1.32 to 1.48). It reverses on CWE-862
(1.68 to 1.84 is the guided arm ahead; the unguided arm's 1.88 on `fix_quality` against 1.79 is
the two invented-member build failures), CWE-287 (1.91 to 1.78: the guided arm adds a
`WWW-Authenticate` header and lockout behaviour the contract did not ask for), CWE-611 (1.83 to
1.50: `fast-xml-parser` swaps that change the XPath the caller used) and CWE-90 (`fix_quality`
2.00 to 1.80 on one no-fix verdict).

By language, `no_harm` A to B: C 1.86 to 1.95, C++ 1.84 to 1.91, C# 1.54 to 1.73, Go 1.76 to
1.71, Java 1.71 to 1.72, JavaScript 1.59 to 1.75, Perl 1.92 to 2.00, PHP 1.77 to 1.76, Python
1.69 to 1.74. Go is the one language where the guided arm loses ground, on CWE-78 timeouts and
format narrowing (a 30-second `CommandContext` that kills legitimate traces; `archive/tar` that
no longer reads the bzip2 and xz archives `tar -tf` did).

**Fable is a stricter `no_harm` judge, and consistent about it.** The rubric pin scores an added
restriction as 1 unless the contract calls for it, and Fable applies that to shapes the Sonnet
panels of runs 17-19 let through: a hostname allowlist beside an argv fix, a 30-second timeout,
a MIME allowlist, a `SameSite=Strict` the original did not set, a `MAX_CONNECTIONS` cap. CWE-78
scores 1.25 on `no_harm` unguided and 1.38 guided because Sonnet adds a hostname or filename allowlist next
to the fix in either arm - 17 of the unguided arm's 21 misses and 15 of the guided arm's 20 carry
a narrowing note. The entries stopped prescribing allowlists in run 18; Sonnet adds them on its
own, and the doctrine change did not reach it. CWE-94 (`no_harm` 1.32 unguided, 1.48 guided) and
CWE-434 (1.60 and 1.55)
have the same shape: sandboxes that reject expressions the original accepted, image re-encodes
that alter legitimate uploads. Whether those are regressions or the correct price of the fix is
the open rubric question from run 19, now with a judge that answers it strictly every time.

**Where the guided arm still loses.** 27 cases where B is at least 0.67 below A on an axis. The
no-fix verdicts (five), the library swap that changes what the caller receives (redis-py
`hset()` dropping the return value, `fast-xml-parser` changing the XPath, an `ImageIO` re-encode),
a constructor signature changed and stated (`Socket` to `Session`), and the added restriction
the entry now says to state and the rubric scores 1 regardless (a `WithExpirationRequired`, a
10 MB buffer cap, `SameSite=Strict`). One entry-attributable slip: `cwe/22/java`'s "reject an absolute
path before resolving" step, added in the run-19 sweep, produced an `isAbsolute` rejection on a
case whose contract accepts absolute paths. Nothing in the list is a namespace or a placeholder - the bucket the runs 18-19 sweeps
closed stays closed for Sonnet.

## The judging protocol

Build line obeyed 10 of 10. Judge splits on `no_harm` were 42 per arm, against 51 and 64 for the
Sonnet panel on Haiku in run 17 - Fable disagrees with itself less. Cost: 180 Fable judges over
three launches (a session limit and an interrupted tool call each ended a launch; every restart
resumed from the valid files on disk) at roughly 60-75k tokens per judge, in line with the Sonnet
panels. Arms: 744 Sonnet agents, 44.1M tokens, about two hours - roughly 2.5 times Haiku's cost
per write-up.

Two operational findings from this run, both recorded in HARNESS.md and the README: rejecting a
foreground tool call kills every background workflow in the session without a notification, and
Sonnet arm agents leave whole-disk `find /` searches and scratch Go files behind when their shell
times out (33 orphaned `find.exe` processes, a `go.mod` in the repo root, a `fixed_*.java`
written into a case directory).

## Limitations

- One sample per arm; the 372-case paired counts are the evidence, the per-CWE rows with fewer
  than ten cases are direction only.
- The gate reflects one environment per language. The jakarta/javax generation of the Spring
  cases is not signalled by the fixture, and one unguided write-up hosting PowerShell through
  `Microsoft.PowerShell.SDK` is `UNCHECKED` because that SDK cannot coexist with the superset's
  pinned SqlClient.
- The narrowing and silent-change counts come from a regular expression over judge notes.
- This is a new judge scale. Compare A against B within this run, and this run against run 21;
  do not compare either against runs 17-19.
