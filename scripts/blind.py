#!/usr/bin/env python3
"""Anonymise run outputs into one blind pool for scoring.

Usage:
    python evals/scripts/blind.py <run-dir> [<run-dir> ...] --out <dir>

Each <run-dir> is one arm's outputs, e.g. evals/runs-v4/A. The directory's own name is the arm
label recorded in the map. Outputs are shuffled by a hash of case+arm, so the ordering is
deterministic and reproducible but carries no arm signal.

Case ids are only unique within a (cwe, language) pair, not across the whole corpus - a few ids
(e.g. MultiFileRedisCommandRelay) are reused for analogous cases in different languages. To avoid
silently colliding on those, an arm's outputs must be laid out as <run-dir>/<cwe>/<language>/
<case-id>.md rather than flat <run-dir>/<case-id>.md.

Two things this does that matter:

- Sections after a self-report heading (Behaviour changes) are stripped. Only some arms are asked
  for one, so its presence alone would identify the arm. What is scored is the code an arm
  produced, not its account of itself.
- Each blinded file is prefixed with the finding the arm was given, so a judge can check the claim
  without opening case.json - which holds the answer.

Writes <out>/<rid>.md and <out>/arm-map.json next to it. (Older invocations of this script wrote
the map to <out>/../arm-map.json - fine for a throwaway --out like /tmp/blind-v4, but a repo-local
--out collided with and overwrote an existing arm-map*.json sitting next to it.)
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CASES = os.path.join(REPO, 'evals', 'cases')

SELF_REPORT = re.compile(r'\n#+\s*Behaviou?r changes', re.I)


def load_cases():
    # Keyed by (cwe, language, id): case ids are only unique within a (cwe, language) pair,
    # not across the whole corpus - several ids (e.g. MultiFileRedisCommandRelay) are reused
    # for analogous cases in different languages. Keying by id alone silently drops one.
    cases = {}
    for cwe in sorted(os.listdir(CASES)):
        for lang in sorted(os.listdir(os.path.join(CASES, cwe))):
            for cid in sorted(os.listdir(os.path.join(CASES, cwe, lang))):
                meta = os.path.join(CASES, cwe, lang, cid, 'case.json')
                if os.path.exists(meta):
                    c = json.loads(io.open(meta, encoding='utf-8').read())
                    c['dir'] = f'evals/cases/{cwe}/{lang}/{cid}'
                    cases[(cwe, lang, cid)] = c
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run_dirs', nargs='+')
    ap.add_argument('--out', required=True)
    ap.add_argument('--prefix', default='R')
    args = ap.parse_args()

    cases = load_cases()
    items = []
    for d in args.run_dirs:
        arm = os.path.basename(os.path.normpath(d))
        for cwe in sorted(os.listdir(d)):
            cwe_dir = os.path.join(d, cwe)
            if not os.path.isdir(cwe_dir):
                continue
            for lang in sorted(os.listdir(cwe_dir)):
                lang_dir = os.path.join(cwe_dir, lang)
                for fn in sorted(os.listdir(lang_dir)):
                    if fn.endswith('.md'):
                        items.append((arm, cwe, lang, fn[:-3], lang_dir))
    items.sort(key=lambda t: hashlib.sha256(f'{t[3]}|{t[1]}|{t[2]}|{t[0]}'.encode()).hexdigest())

    shutil.rmtree(args.out, ignore_errors=True)
    os.makedirs(args.out, exist_ok=True)

    mapping = {}
    missing = []
    for i, (arm, cwe, lang, cid, d) in enumerate(items, 1):
        rid = f'{args.prefix}{100 + i}'
        c = cases.get((cwe, lang, cid))
        if c is None:
            missing.append(f'{cwe}/{lang}/{cid}')
            continue
        mapping[rid] = {'arm': arm, 'case': cid, 'cwe': c['cwe'], 'language': c['language'],
                        'kind': c['kind'], 'depth': c['depth'], 'group': c['group'],
                        'source': c['source']}
        body = io.open(os.path.join(d, cid + '.md'), encoding='utf-8').read()
        body = SELF_REPORT.split(body, maxsplit=1)[0].rstrip() + '\n'
        f = c['finding']
        io.open(os.path.join(args.out, rid + '.md'), 'w', encoding='utf-8', newline='').write(
            f"# {rid}\n\n"
            f"Case directory: `{c['dir']}/` ({c['depth']} file(s) in the call chain)\n"
            f"Scanner reported: {f['cwe']} ({f['name']}) in `{f['file']}` line {f['sink_line']}\n"
            f"Reported sink: `{f['sink_code']}`\n\n---\n\n{body}\n")

    out_map = os.path.join(args.out, 'arm-map.json')
    io.open(out_map, 'w', encoding='utf-8', newline='').write(json.dumps(mapping, indent=2) + '\n')

    print(f'{len(mapping)} runs blinded -> {args.out}')
    print('per arm:', {a: sum(1 for v in mapping.values() if v['arm'] == a)
                       for a in sorted({v['arm'] for v in mapping.values()})})
    print('map ->', out_map)
    if missing:
        print('WARNING no case.json for:', ', '.join(sorted(set(missing))))

    leaked = [f for f in sorted(os.listdir(args.out))
              if SELF_REPORT.search(io.open(os.path.join(args.out, f), encoding='utf-8').read())]
    print('leak check (self-report section still present):', leaked or 'none')


main()
