#!/usr/bin/env python3
"""Join blind scores to the arm map and emit the comparison tables.

Usage:
    python evals/scripts/analyse.py --map <arm-map.json> --scores <dir-of-judge*.json> [--out <file>]

Every judge scores every run, so scores are AVERAGED per run rather than merged - a dict update
would silently keep whichever judge sorted last and throw the rest away.

Scored fields, all optional so the same script serves runs with different rubrics:
    fix_quality (0-2), no_harm (0-2), source_identified (0-2), verdict_correct (bool)
"""
import argparse
import glob
import io
import json
import os

NUM = ('source_identified', 'fix_quality', 'no_harm')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--map', required=True)
    ap.add_argument('--scores', required=True)
    ap.add_argument('--out')
    args = ap.parse_args()

    mapping = json.loads(io.open(args.map, encoding='utf-8').read())
    judges = {}
    for f in sorted(glob.glob(os.path.join(args.scores, 'judge*.json'))):
        judges[os.path.basename(f)] = json.loads(io.open(f, encoding='utf-8').read())
    if not judges:
        raise SystemExit(f'no judge*.json under {args.scores}')
    print('judges:', {k: len(v) for k, v in judges.items()})

    rows = []
    for rid, m in mapping.items():
        per = [j[rid] for j in judges.values() if rid in j]
        if not per:
            continue
        r = dict(m, rid=rid, n_judges=len(per))
        for k in NUM:
            vals = [x[k] for x in per if k in x]
            r[k] = sum(vals) / len(vals) if vals else None
            r['spread_' + k] = (max(vals) - min(vals)) if vals else 0
        vc = [bool(x['verdict_correct']) for x in per if 'verdict_correct' in x]
        r['verdict'] = (sum(vc) / len(vc)) if vc else None
        rows.append(r)

    missing = sorted(set(mapping) - {r['rid'] for r in rows})
    if missing:
        print('MISSING SCORES:', ', '.join(missing))
    disagree = {k: sum(1 for r in rows if r['spread_' + k]) for k in NUM}
    print('runs where judges disagreed:', disagree, 'of', len(rows))

    arms = sorted({r['arm'] for r in rows})
    out = []

    def agg(sel):
        sub = [r for r in rows if sel(r)]
        if not sub:
            return None
        a = {'n': len(sub)}
        for k in NUM + ('verdict',):
            vals = [r[k] for r in sub if r.get(k) is not None]
            a[k] = sum(vals) / len(vals) if vals else None
        return a

    def cell(v, pct=False):
        if v is None:
            return '-'
        return f'{v*100:.0f}%' if pct else f'{v:.2f}'

    def table(title, groups):
        out.append(f'{title}\n')
        out.append('| Set | n | verdict | source /2 | fix /2 | no-harm /2 |')
        out.append('|---|---|---|---|---|---|')
        for label, sel in groups:
            a = agg(sel)
            if not a:
                out.append(f'| {label} | - | - | - | - | - |')
                continue
            out.append(f"| {label} | {a['n']} | {cell(a['verdict'], True)} | "
                       f"{cell(a['source_identified'])} | {cell(a['fix_quality'])} | "
                       f"{cell(a['no_harm'])} |")
        out.append('')

    table('## Results', [(a, lambda r, x=a: r['arm'] == x) for a in arms])

    table('### By CWE', [(f'CWE-{c} / {a}', lambda r, x=a, y=c: r['arm'] == x and r['cwe'] == y)
                         for c in sorted({r['cwe'] for r in rows}, key=int) for a in arms])

    table('### By language', [(f"{lg} / {a}", lambda r, x=a, y=lg: r['arm'] == x
                               and r['language'] == y)
                              for lg in sorted({r['language'] for r in rows}) for a in arms])

    table('### By case source', [(f'{s} / {a}', lambda r, x=a, y=s: r['arm'] == x
                                  and r['source'] == y)
                                 for s in sorted({r['source'] for r in rows}) for a in arms])

    out.append('### Per-run\n')
    out.append('| run | arm | case | CWE | lang | source | fix | no-harm |')
    out.append('|---|---|---|---|---|---|---|---|')
    for r in sorted(rows, key=lambda r: (int(r['cwe']), r['case'], r['arm'])):
        out.append(f"| {r['rid']} | {r['arm']} | {r['case']} | {r['cwe']} | {r['language']} | "
                   f"{r['source']} | {cell(r['fix_quality'])} | {cell(r['no_harm'])} |")

    text = '\n'.join(out) + '\n'
    if args.out:
        io.open(args.out, 'w', encoding='utf-8', newline='').write(text)
        print('written ->', args.out)
    print()
    print(text)


main()
