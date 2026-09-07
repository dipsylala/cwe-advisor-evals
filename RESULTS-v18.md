# Run 18 - targeted re-run after the allowlist doctrine and package-name edits

A targeted run (HARNESS.md, "What a run is"): the guided arm re-sampled on 115 cases whose
entries changed after run 17, judged in one pool beside run 17's frozen text for the same cases.
Two questions, two case groups:

- **Doctrine set** (78 cases: every CWE-22, 77, 78 and 90 case in every language). The entries
  stopped prescribing an allowlist as a default step; the API fix is the remediation and an
  allowlist is added only where the application defines the value's format. Does the guided
  arm's `no_harm` recover?
- **Package set** (37 cases: the Java cases of the other entries that gained package names for
  the third-party classes they recommend, plus CWE-79 and CWE-94 Java from the run-17 fixes).
  Do the build failures go away?

Sets in the pool: `A` (run 17's unguided text), `B-pre` (run 17's guided text), `B-post` (fresh
Haiku 4.5 guided sample under the byte-identical prompt). Arms: Haiku 4.5
(`claude-haiku-4-5-20251001`); judges: three `cwe-judge` Sonnet 5 agents per segment, 28
segments, and for the first time the blinded header carries the compile gate's `Build:` line and
the judges are told not to compile.

## Gate

| Group | Set | n | OK | FAIL | Kinds of FAIL |
| --- | --- | --- | --- | --- | --- |
| package | A | 37 | 31 | 3 | missing-import 2, unresolved-member 1 |
| package | B-pre | 37 | 28 | 8 | missing-import 5, unresolved-name 2, signature 1 |
| package | B-post | 37 | 33 | 3 | unresolved-name 2, other 1 |
| doctrine | A | 78 | 78 | 0 | |
| doctrine | B-pre | 78 | 74 | 3 | missing-import 2, unresolved-name 1 |
| doctrine | B-post | 78 | 76 | 2 | unresolved-name 1, other 1 |

The package edits did what they were for: the guided arm's missing-import failures on those 37
cases went from five to none, and its total from eight to three (the `SpaCsrfTokenRequestHandler`
import still appears once even though the entry now says the class is not shipped; an invented
`HttpHeaders.X_CONTENT_TYPE_OPTIONS`; a duplicate class in a multi-file rewrite). One first-pass
failure was an environment gap - `commons-net`'s `FTPClient`, which `cwe/77/java` recommends -
and the superset now carries it.

## Judged

| Group | Set | n | fix_quality | no_harm | clean | no_harm splits |
| --- | --- | --- | --- | --- | --- | --- |
| package | A | 37 | 1.60 | 1.66 | 22 | 10 |
| package | B-pre | 37 | 1.53 | 1.60 | 24 | 9 |
| package | B-post | 37 | **1.84** | **1.81** | 27 | 8 |
| doctrine | A | 78 | 1.88 | 1.83 | 49 | 14 |
| doctrine | B-pre | 78 | 1.91 | 1.66 | 44 | 15 |
| doctrine | B-post | 78 | 1.86 | 1.68 | 43 | 21 |
| all | A | 115 | 1.79 | 1.78 | 71 | 24 |
| all | B-pre | 115 | 1.79 | 1.64 | 68 | 24 |
| all | B-post | 115 | 1.86 | 1.72 | 70 | 29 |

Paired per case, B-pre to B-post: package set `fix_quality` up on 8, down on 1, tied on 28;
`no_harm` up on 9, down on 4. Doctrine set `fix_quality` up on 4, down on 9; `no_harm` up on 19,
down on 16, tied on 43.

**Package set: the edits worked.** Naming the package of every third-party class the entry
recommends moved the guided arm from below the unguided arm (1.53 / 1.60 against 1.60 / 1.66)
to well above it (1.84 / 1.81) on the same 37 cases, with the build failures accounting for most
of the gap closed. That is a sample of one on 37 cases, but the direction matches the gate's
mechanical count.

**Doctrine set: the target moved, the metric did not.** The guided arm stopped adding allowlists:
anchored character-class regexes in its doctrine-set write-ups went from 9 to 0 and any mention
of an allowlist from 22 to 10, below the unguided arm's 12. The judges saw it - unanimous
"narrowing" verdicts on the guided arm's `no_harm` misses fell from 12 to 2 - and `no_harm`
stayed where it was (1.66 to 1.68) because a different loss took the vacated place: silent
behaviour change rose from 7 to 13 unanimous notes. Reading them, it is the CWE-78 advice to
eliminate the shell in favour of a library doing what run 17 already showed it does - `ping`
replaced by a TCP connect or `InetAddress.isReachable()`, a return value dropped, a `ctx` no
longer honoured, a response body reformatted - plus a new narrowing shape the entries also
prescribe, a leading-`-` rejection for option injection (CWE-88), which the pin scores as
narrowing too. The regression the run-17 results file warned of also appears once:
`78/java/BenchmarkTest00006` removed the shell and then wrote the raw parameter into an HTML
response, trading CWE-78 for CWE-79 (`no_harm` 2.00 to 0.67).

By CWE in the doctrine set (`no_harm`, A / B-pre / B-post): CWE-22 1.90 / 1.90 / 1.81, CWE-77
1.65 / 1.50 / 1.60, CWE-78 1.82 / 1.54 / 1.54, CWE-90 2.00 / 1.70 / 1.90. CWE-90, where the
allowlist was the whole story, recovered; CWE-78, where the shell-elimination rewrite is the
story, did not.

`cwe/78/go` was edited once more after reading the notes: its "validate only where the
application defines the format (a map of known values, a hostname pattern)" had the guided arm
read "hostname pattern" as licence to add one. The example now says a hostname is not such a
value unless the application restricts hosts. Unmeasured.

## The judging protocol

The `Build:` line was obeyed: all 19 `FAIL` write-ups in the pool scored 0 on `fix_quality`
from all three judges. Panel drift on the frozen text, run-17 panel to this one: A 1.82 / 1.78
to 1.79 / 1.78, B-pre 1.86 / 1.58 to 1.79 / 1.64 (the `fix_quality` drop is the eleven B-pre
build failures now scoring 0 consistently; the `no_harm` rise is the same write-ups no longer
also losing `no_harm` for "does not compile"). Identical means on 79 and 76 of 115.

The cost did not fall. 345 write-ups took 84 agents, 6.1M subagent tokens and 28 minutes -
17.8k tokens per scored write-up against run 17's 16k. Tool calls per judge fell from 7.8 to
5.5, so the compile turns did go; what remains is reading an 80 KB bundle and writing the
scores, and that is the floor of this protocol. The gate line is still worth carrying for
consistency (19 of 19 against run 17's 24 of 35), not for tokens.

## What this establishes

- Naming a class's package in the entry is the cheapest content change that has moved the
  guided arm in eighteen runs: build failures 8 to 3 and `no_harm` 1.60 to 1.81 on the 37 Java
  cases, from one pass over the entries that an index of the JDK and the superset classpath
  drove.
- The allowlist doctrine change removed the shape it targeted and revealed the next one. The
  guided arm's remaining `no_harm` losses in the injection families are behaviour changes made
  while replacing the sink with a library, and the entries already warn against them in prose;
  runs 15 and 16 say prose does not move Haiku on that kind of slip. A mechanical check - the
  gate reporting lines changed outside the sink's function, or a test per case that exercises
  the original contract - is the next instrument, not another bullet.
- Judges with the gate's verdict in hand agree with it every time and drift less; they do not
  cost less.

## Limitations

- One guided sample of 115 cases; the doctrine set's paired counts (19 up, 16 down) are inside
  the sample noise, and the package set's 37 cases carry the whole of that result.
- Two arm-B write-ups still did not build for reasons the entries could not have prevented, and
  the gate reflects one dependency environment per language.
- The narrowing and silent-change counts come from a regular expression over judge notes.

## Cost

Arms: 116 Haiku agents, 5.4M subagent tokens, 14 minutes. Gate: minutes, no tokens. Judges: 84
Sonnet agents, 6.1M tokens, 28 minutes.
