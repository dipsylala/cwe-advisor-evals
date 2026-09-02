# TODO

Live pending work for the eval corpus and harness only. Corpus mechanics, sourcing rules, and the
current top-15 fix-quality target live in `README.md`; the arm/judge runbook lives in `HARNESS.md`;
known measurement gaps live in `README.md`'s "Known gaps" section - this file does not repeat any
of those. Completed work's reasoning lives in `git log` commit messages, not here.

## Corpus campaigns

- Per-language coverage (breadth): 258 `(cwe, language)` slots remain out of the original 318
  missing (root-only CWEs with no language subfolder are out of scope). Continue in ~15-case
  batches, one workflow run each, checking each batch's output before the next.
- Top-15 depth: remaining CWEs in rank order: 78, 89 (both need 2 more per slot to reach 3), 94,
  125, 287, 352, 416, 434, 787, 862. The corpus this campaign originally mined pattern shapes from
  is no longer part of the parent repo's source - pull patterns from OWASP cheat sheets, framework
  docs, or the language entry's own `Key Principles` instead.
- Multi-file depth cases exist only for CWE-79 (7 languages) and CWE-77 (4 languages) at the 3-case
  single-file target; not extended to other top-15 CWEs or applied as a default - decide if wanted.

## Prioritization

MITRE rank is a proxy for exploitation data, not for what a SAST tool actually flags in source. If
scanner output naming which CWEs actually arrive becomes available, prioritize by that instead of
rank order.
