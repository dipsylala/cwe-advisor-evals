# TODO

Live pending work for the eval corpus and harness only. Corpus mechanics, sourcing rules, and the
current top-15 fix-quality target live in `README.md`; the arm/judge runbook lives in `HARNESS.md`;
known measurement gaps live in `README.md`'s "Known gaps" section - this file does not repeat any
of those. Completed work's reasoning lives in `git log` commit messages, not here.

## Corpus campaigns

- Per-language coverage (breadth): 222 `(cwe, language)` slots remain uncovered, out of 339 total
  in the knowledge base (root-only CWEs with no language subfolder are out of scope) - recounted
  2026-09-02 via a directory diff (`cwe/{id}/{lang}/` vs `evals/cases/{cwe}/{lang}/`), since the
  tracked "258 of 318" figure had drifted stale as new CWE entries were added independent of this
  campaign. Continue in ~15-case batches, one workflow run each, checking each batch's output
  before the next.
- Top-15 depth: CWE-78 and CWE-89 are done (3 `authored` cases per language across all 6 languages
  each); CWE-94 and CWE-125 are done (3 `authored` cases per language across all their languages -
  both had zero before this pass). Remaining CWEs in rank order: 287, 352, 416, 434, 787, 862. The
  corpus this campaign originally mined pattern shapes from is no longer part of the parent repo's
  source - pull patterns from OWASP cheat sheets, framework docs, or the language entry's own
  `Key Principles` instead.
- Multi-file depth cases exist only for CWE-79 (7 languages) and CWE-77 (4 languages) at the 3-case
  single-file target; not extended to other top-15 CWEs or applied as a default - decide if wanted.
