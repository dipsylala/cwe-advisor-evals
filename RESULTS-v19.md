# Run 19 - targeted re-run after the run-17/18 judge-note sweep

A targeted run (HARNESS.md, "What a run is"): the guided arm re-sampled on the 138 cases whose
entries changed in the sweep that followed runs 17 and 18, judged in one pool beside the frozen
unguided text and the most recent guided text for the same cases. The sweep came from reading
every guided-arm loss in the two runs' judge notes (47 and 17 cases) and editing the entry that
had produced it; thirty entry files changed. Five groups, five questions:

- **Ping** (6 CWE-78 cases whose original runs `ping` or `traceroute`). The CWE-78 php,
  javascript and python entries said "use fsockopen / net / socket instead of ping", which is a
  TCP connect and not an ICMP echo; the root and every language file now say `ping` has no
  library equivalent and stays as a command with the host as its own argument. Does the guided
  arm stop swapping the semantics?
- **CWE-22** (24 cases, every language). The root, java, javascript, csharp and go entries no
  longer prescribe a `..` substring test beside a containment check, and the single-component
  rule is scoped to upload filenames. Does the guided arm stop narrowing?
- **CWE-78** (the other 21 cases). Leading-`-` guidance reordered across the family: insert
  `--` where the program honours it, reject only where it does not.
- **Namespace** (7 cases: the build failures the compiler pinned to a name the entry could
  carry - `System.Data` for `SqlDbType`, `Enyim.Caching.Memcached` for `StoreMode`,
  `Microsoft.AspNetCore.Antiforgery`, `System.IO.File` inside a controller,
  `java.awt.image.BufferedImage`, `ResponseEntity.BodyBuilder`, the `X-Content-Type-Options`
  header as a string). Do they build?
- **CWE-862** (25 cases) and **other** (55 cases across CWE-77, 89, 94, 117, 326, 347, 352, 434,
  611, 787): API-shape facts the judges had verified against real packages (`Execute(params
  object[])`, `forReadOnlyDataBinding()`, `$name` bind placeholders, `parseTagValue: false`,
  `res.sendFile()`, keep-the-existing-key, `CrossOriginProtection.Check()`, `Store.connect()`,
  the `\u000a` output form, no fallback secret, "the fix adds the missing check, it does not
  redesign the rules", identity-must-be-set-upstream, audit-log truncation, keep-the-rule-language).

Sets in the pool: `A` (run 17's unguided text, frozen), `B-pre` (run 18's guided text where that
run covered the case - 74 cases - else run 17's), `B-post` (fresh Haiku 4.5 guided sample under
the byte-identical prompt). Arms: Haiku 4.5 (`claude-haiku-4-5-20251001`); judges: three
`cwe-judge` Sonnet 5 agents per segment, 29 segments, Build line in the header.

## Gate

| Group | Set | n | OK | FAIL | Kinds of FAIL |
| --- | --- | --- | --- | --- | --- |
| namespace | A | 7 | 7 | 0 | |
| namespace | B-pre | 7 | 1 | 6 | missing-import 3, unresolved-name 2, other 1 |
| namespace | B-post | 7 | 7 | 0 | |
| ping | all three | 6 | 6 | 0 | |
| cwe22 | all three | 24 | 24 | 0 | |
| cwe78 | all three | 21 | 21 | 0 | |
| cwe862 | A | 25 | 22 | 2 | missing-import 2 |
| cwe862 | B-pre | 25 | 24 | 0 | |
| cwe862 | B-post | 25 | 22 | 2 | unresolved-member 2 |
| other | A | 55 | 53 | 0 | |
| other | B-pre | 55 | 50 | 4 | unresolved-member, other, syntax, signature |
| other | B-post | 55 | 52 | 2 | unresolved-member 1, signature 1 |
| all | A | 138 | 133 | 2 | |
| all | B-pre | 138 | 126 | 10 | |
| all | B-post | 138 | 132 | 4 | |

The namespace lines did what they were for: six build failures to none, and `SqlDbType`,
`StoreMode`, `IAntiforgery`, `ControllerBase.File`, `BufferedImage` and the header constant do
not appear in any note. The guided arm's four remaining failures are members it invented on the
fixture's own types (`ChatMessage.UserId`, `Order.getOwnerId()`), one on Spring's
(`SimpleEvaluationContext.setRootObject()`, which exists only on the standard context) and one
JEXL signature (`sandbox.allow(Number.class)` where a class name is expected). One of B-pre's
ten is the known mypy false positive on `AESGCM.generate_key(bit_length=256)` (RESULTS-v17.md).

Two first-pass rows were environment gaps under the triage rule: `file-type` (which
`cwe/434/javascript` recommends) and `xml2js` were not in the JavaScript superset; both were
added and the rows re-gated to `OK`. A harness lesson as well: running the seven per-language
gates in parallel exhausted the machine's memory and produced twelve `FAIL` rows whose notes were
JVM, .NET, Node and PHP allocation failures. Every one passed when re-run serially. A note that
reads as an allocation failure is the gate's fault, not the fix's, and HARNESS.md now says so.

## Judged

| Group | Set | n | fix_quality | no_harm | clean | no_harm < 2 |
| --- | --- | --- | --- | --- | --- | --- |
| ping | A | 6 | 2.00 | 1.83 | 4 | 2 |
| ping | B-pre | 6 | 2.00 | 1.33 | 2 | 4 |
| ping | B-post | 6 | 1.83 | **2.00** | 4 | 0 |
| cwe22 | A | 24 | 1.88 | 1.92 | 17 | 4 |
| cwe22 | B-pre | 24 | 1.96 | 1.83 | 16 | 7 |
| cwe22 | B-post | 24 | 1.97 | 1.82 | 17 | 5 |
| cwe78 | A | 21 | 1.83 | 1.79 | 13 | 4 |
| cwe78 | B-pre | 21 | 1.84 | 1.60 | 11 | 10 |
| cwe78 | B-post | 21 | 1.89 | **1.81** | 14 | 5 |
| cwe862 | A | 25 | 1.67 | 1.76 | 18 | 5 |
| cwe862 | B-pre | 25 | 1.87 | 1.92 | 20 | 3 |
| cwe862 | B-post | 25 | 1.67 | 1.77 | 17 | 7 |
| namespace | A | 7 | 1.81 | 1.67 | 4 | 2 |
| namespace | B-pre | 7 | 0.29 | 0.57 | 0 | 7 |
| namespace | B-post | 7 | **1.90** | **1.76** | 4 | 2 |
| other | A | 55 | 1.78 | 1.75 | 37 | 14 |
| other | B-pre | 55 | 1.78 | 1.60 | 34 | 19 |
| other | B-post | 55 | 1.88 | 1.72 | 39 | 16 |
| all | A | 138 | 1.79 | 1.79 | 93 | 31 |
| all | B-pre | 138 | 1.77 | 1.64 | 83 | 50 |
| all | B-post | 138 | **1.86** | **1.78** | 95 | 35 |

Paired per case, B-pre to B-post over all 138: `fix_quality` up on 15, down on 12, tied on 111;
`no_harm` up on 38, down on 22, tied on 78.

**The guided arm is now level with the control on `no_harm` and ahead on `fix_quality` for
these cases.** Before the sweep it was 0.15 behind on `no_harm` (1.64 against 1.79) on the very
cases its entries had shaped; after, 1.78 against 1.79, with `fix_quality` 1.86 against 1.79 and
build failures 10 to 4. Clean write-ups (all three judges 2 on both axes) went 83 to 95, two more
than the control.

**Ping: the swap stopped.** Both PHP write-ups dropped the TCP probe and kept `ping`; no
write-up in the group calls `fsockopen`, `isReachable()` or `net.connect()`. `no_harm` 1.33 to
2.00. The two `fix_quality` points it gave back are the same judges now asking for a
leading-`-` rejection on the host - see the rubric note below.

**CWE-78: recovered past the control.** `no_harm` 1.60 to 1.81 on the 21 non-ping cases and
1.50 to 1.86 on all 28, against the control's 1.79. Leading-`-` rejections in the guided text
went 5 to 0 and `--` insertions 1 to 3.

**CWE-22: the shape moved, the score did not.** The Zip Slip case lost its single-component
check and `..` substring checks beside containment went 3 to 1, but `no_harm` stayed 1.83 to
1.82: the remaining misses are a removed `URLDecoder.decode()` call scored as a behaviour change
beside the fix (two Benchmark cases), a `toRealPath()` on a file that may not exist, and a
plugin allowlist hardcoding two guessed names. Each is a real note; none is
the shape the edit targeted.

**Namespace: 0.29 / 0.57 to 1.90 / 1.76**, the same result as run 18's package sweep in Java,
now for C# and the JDK's own types. Naming the namespace is still the cheapest edit there is.

**CWE-862 moved down, and the edit is not why.** `B-pre` here is run 17's text (run 18 did not
cover CWE-862) and scored an unusually high 1.87 / 1.92; the fresh sample scored 1.67 / 1.77,
level with the control. Two of its four points are the two build failures on invented members,
and the shape the root bullet targeted - invented permissions beside the fix - appears in one
judge note before and one after. A sample of one on 25 cases that regressed to the control is
not evidence for or against the bullet.

**What did not move.** CWE-94 (1.50 / 1.04 to 1.46 / 1.21, eight cases): the guided arm swapped
the stored rules' language for JEXL again despite the new "keep the language" bullet, invented
`setRootObject()` on the simple SpEL context, and passed a `Class` where JEXL wants a name.
CWE-77 (1.62 / 1.46 to 1.75 / 1.54): the constructor changes from `Socket` to a client type
are now stated in the write-ups, and the judges score a stated signature change 1 all the same.
CWE-434 java: the entry's image re-encode step is scored as a behaviour change (bytes altered,
images `ImageIO` cannot decode rejected) on three of five cases - the rubric and the entry
disagree there the way they did on allowlists, and that is a decision, not a slip.

**Two entry defects found by this run's notes, both verified against the jar and fixed,
unmeasured.** `cwe/77/java` recommended Commons Net's `FTPClient` for the FTP case, and a judge
decompiled it: `FTP.buildMessage()` appends command, space, argument and CRLF with no check, so a
filename carrying `\r\n` still injects through the library (confirmed with javap on 3.11.1); the
entry now says the library replaces the socket and rejecting CR/LF closes the vector. And the
`forReadOnlyDataBinding()` line added in the sweep did not say how the root object gets in, so the
arm called `setRootObject()`, which only `StandardEvaluationContext` has; the entry now names
`getValue(context, rootObject)` and the builder's `withRootObject(...)`.

## The judging protocol

The Build line was obeyed 16 of 16 (`FAIL` write-ups scoring 0 on `fix_quality` from all three
judges). Panel drift on the frozen A text, run-17 panel to this one: 1.82 / 1.80 to 1.79 / 1.79,
identical means on 114 and 112 of 138. One judge file carried an invalid JSON escape (`\'` inside
a note) and was repaired mechanically before validation; the scores were not touched.

One rubric tension surfaced by the leading-`-` change: judge notes citing option or flag
injection on the CWE-78 guided text went 8 to 14. With the rejection gone, judges now dock
`fix_quality` where a host value could begin with `-` and the program does not take `--` (`ping`
does not), which is the CWE-88 gap the entries describe. The entry's answer is "reject only where
`--` is not honoured, and say so"; the arm did neither on two ping cases. That is a case for the
entry to name `ping` as one of the programs where the rejection is required, not for reversing
the reorder.

## Composite: the latest guided text over the whole corpus

Runs 18 and 19 replaced the guided text for 179 of the 372 cases (41 last sampled in run 18,
138 in run 19). Taking each case's most recent guided sample with the scores it received, against
run 17's unguided control:

| | fix_quality | no_harm | Clean | Does not build |
| --- | --- | --- | --- | --- |
| Unguided (run 17) | 1.80 | 1.76 | 256 | 16 |
| Guided, run 17 | 1.91 | 1.74 | 263 | 18 |
| Guided, latest text | 1.92 | 1.82 | 288 | 7 |

Guided is ahead on `fix_quality` for 63 cases and behind on 19; on `no_harm` ahead on 62 and
behind on 46. The composite mixes three judge panels, but the control's drift across them is
0.03 or less, and every touched case was re-sampled because its entry changed, not selected for
its score. The per-language form of this table is in the parent repository's README.

## Limitations

- One guided sample per group; the ping group is six cases and the namespace group seven, so
  those rows are direction, not magnitude.
- The composite's untouched 193 cases carry run-17 scores from a different panel than the 179
  touched ones; the A drift bounds the panel effect at about 0.03.
- The narrowing and silent-change counts come from a regular expression over judge notes.

## Cost

Arms: 138 Haiku agents, 6.4M subagent tokens, 14 minutes. Gate: minutes, no tokens, plus the
serial re-run. Judges: 87 Sonnet agents, 7.0M tokens, 37 minutes - 16.9k tokens per scored
write-up, unchanged from runs 17 and 18.
