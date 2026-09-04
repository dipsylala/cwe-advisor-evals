# Validation harness - run 14 results

56 runs (14 cases x 4 sets), **Haiku 4.5 arms, Sonnet 5 judges**, `must_preserve` in the header.
The 14 cases are every case in the four `(cwe, language)` slots whose entries were edited after run
13 surfaced gaps on them: `90/javascript` (1), `79/python` (4), `94/python` (5), `416/c` (4). Same
design as run 12: A-pre/B-pre are run 13's write-ups for these cases copied verbatim, A-post/B-post
are fresh runs under the byte-identical run-11 prompt after the edits, all four sets in one blind
pool.

The four edits, each verified before writing (see RESULTS-v13.md): `cwe/90/javascript` names
ldapjs's own filter objects and `ldap-escape`, and says `ldapjs-escape` does not exist;
`cwe/79/python` says `flask.escape`/`Markup` are gone in Flask 3.x, import from `markupsafe`;
`cwe/94/python` says an AST allowlist that permits variables needs `ast.Name` and `ast.Load`;
`cwe/416/c` says the generation counter lives in the owner's slot table, never in the object.

## Answer: all four closed

| Set | n | fix /2 | no-harm /2 | clean (2.00/2.00, all judges) |
| --- | --- | --- | --- | --- |
| A-pre | 14 | 1.50 | 1.52 | 8 |
| A-post | 14 | 1.40 | 1.29 | 5 |
| B-pre | 14 | 1.52 | 1.43 | 7 |
| B-post | 14 | **1.98** | **1.88** | **10** |

The control moved -0.10 / -0.23 with nothing changed for it, the same fresh-sample swing runs 12
and 13 showed, so the aggregate is again not the evidence. The targets are:

| Case | B-pre | B-post | A-pre | A-post | What the B-post write-up does |
| --- | --- | --- | --- | --- | --- |
| 90/javascript `LdapFilterFromQuery` | 0.00/0.00 | **2.00/2.00** | 0.00/0.00 | 0.00/0.00 | filter object / `ldap-escape`; no `ldapjs-escape` |
| 94/python `FlaskRenderTemplateStringSSTI` | 0.33/1.33 | **2.00/2.00** | 2.00/2.00 | 2.00/2.00 | `markupsafe` import, no `from flask import escape` |
| 94/python `EvalRestrictedBuiltinsFormula` | 2.00/1.00 | 2.00/1.67 | 1.00/1.00 | 2.00/1.00 | `ast.Load` in the allowlist; one judge: `//` and `%` exceed the contract's `+ - * /` |
| 416/c `DoubleFreeCallbackStructField` | 0.00/1.00 | **2.00/2.00** | 2.00/2.00 | 1.67/2.00 | no counter read through the stale pointer |

The `LdapFilterFromQuery` row is the cleanest signal in the run: the unguided arm scored 0.00/0.00
in run 13 and again here, the guided arm went from the same 0.00/0.00 to clean, and the only thing
that changed between the two guided samples is the entry now naming an API that exists.

## The other ten cases

Unchanged at 2.00/2.00 for the guided arm: five. Three moved:

- `79/python/DjangoMarkSafeMisuse` 2.00/0.00 -> 2.00/2.00 - not a target; the run-13 sample had
  broken the page, this one did not. Sample variance in the guided arm's favour this time.
- `79/python/MultiFileViewRelayXss` 1.00/2.00 -> 1.67/2.00 - one judge notes `html.escape()` on the
  value still leaves it inside `render_template_string()` as template source, so `{{ }}` syntax
  survives. Correct, and `cwe/79/python` lists that sink but does not say the value must go in as a
  template variable rather than into the template text. Noted, not edited.
- `94/python/ImportlibDynamicModuleName` 2.00/2.00 -> 2.00/1.33 - the allowlist remaps plugins to an
  invented package path; a slip.

Judge disagreement: `fix_quality` 5/56, `no_harm` 12/56.

## What run 14 establishes

1. **The four run-13 fixes work where they were aimed** - three targets to a unanimous clean score,
   the fourth to 2.00/1.67 on a contract detail the entry does not (and should not) carry.
2. **The measure-trace-fix-retest loop now has four iterations of evidence** (runs 8-10, 11-12,
   11-13, 13-14), each closing the specific cases it named while the control arm shows the sample
   floor.
3. **One more entry gap is on the list**: `cwe/79/python` on `render_template_string()` - escaping
   the value is not the fix when the value is being compiled as template source.

## Limitations

- **n=14.** Aggregates on this pool mean nothing; the per-case table is the result.
- **Pre is re-judged run-13 text, post is a fresh sample**, as in run 12.
- **Judging sharded 2 x 3.** Five post outputs were nested one directory too deep and flattened
  before blinding; two empty mangled-path directories left by run 13 agents were removed.
