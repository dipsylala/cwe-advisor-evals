#!/usr/bin/env python3
"""Join blind scores to the arm map and emit the comparison tables, plus the derived claims a
results file or README makes in prose.

Usage:
    python evals/scripts/analyse.py 21                  # one run, by the repo's v-suffix convention
    python evals/scripts/analyse.py 20 21               # two runs side by side
    python evals/scripts/analyse.py 21 --arrow-unicode  # tables use an arrow instead of ->
    python evals/scripts/analyse.py --map <arm-map.json> --scores <dir> [--out <file>]

A run number N reads evals/arm-map-vN.json, evals/scores-vN/ and, when present,
evals/runs-vN/gate.json. Label a run with --label (repeatable, in the order the runs are given).

Every judge scores every write-up, so scores are AVERAGED per write-up rather than merged - a dict
update would silently keep whichever judge sorted last and throw the rest away. A write-up counts
as `clean` when every judge gave 2 on both axes.

Why the "Derived claims" section exists: the numbers in these tables have always been right, and
the prose about them has not. Two claims in the parent README were wrong at different times - a
per-language cell dismissed as sampling noise when it was a reproducible entry defect, and a count
of declining cells that was three when it was ten - both written from memory of a table rather than
recomputed. Anything a write-up asserts *about* the table (how many cells moved, which moves are
material, which are ceiling artefacts, which samples are too small to characterise) is printed
here so it can be copied rather than recalled.

Scored fields, all optional so the same script serves runs with different rubrics:
    fix_quality (0-2), no_harm (0-2), source_identified (0-2), verdict_correct (bool)
"""
import argparse
import glob
import io
import json
import os
import statistics

NUM = ('source_identified', 'fix_quality', 'no_harm')
AXES = ('fix_quality', 'no_harm')
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATERIAL = 0.05          # a per-language move larger than this is called out rather than pooled
CEILING = 1.95           # an unguided score at or above this can barely move up
SMALL_N = 5              # below this, a language mean is one or two write-ups


def load_run(map_path, scores_dir, gate_path=None):
    mapping = json.loads(io.open(map_path, encoding='utf-8').read())
    judges = {}
    for f in sorted(glob.glob(os.path.join(scores_dir, 'judge*.json'))):
        judges[os.path.basename(f)] = json.loads(io.open(f, encoding='utf-8').read())
    if not judges:
        raise SystemExit(f'no judge*.json under {scores_dir}')
    gate = json.loads(io.open(gate_path, encoding='utf-8').read()) if gate_path and os.path.exists(gate_path) else {}

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
        r['clean'] = all(r.get(a) == 2 for a in AXES if r.get(a) is not None)
        key = f"{m['arm']}/{m['cwe']}/{m['language']}/{m['case']}"
        r['status'] = gate.get(key, {}).get('status', '')
        r['kind'] = gate.get(key, {}).get('kind', '')
        rows.append(r)
    missing = sorted(set(mapping) - {r['rid'] for r in rows})
    return rows, missing, len(judges)


def mean(rows, field):
    vals = [r[field] for r in rows if r.get(field) is not None]
    return statistics.mean(vals) if vals else None


def fmt(v):
    return '-' if v is None else f'{v:.2f}'


class Run:
    def __init__(self, rows, missing, n_judge_files, label):
        self.rows, self.missing, self.n_judge_files, self.label = rows, missing, n_judge_files, label
        self.arms = sorted({r['arm'] for r in rows})

    def sel(self, arm=None, **eq):
        return [r for r in self.rows
                if (arm is None or r['arm'] == arm) and all(r.get(k) == v for k, v in eq.items())]

    def cell(self, arm, axis, **eq):
        return mean(self.sel(arm, **eq), axis)

    def groups(self, field):
        vals = {r[field] for r in self.rows if r.get(field) is not None}
        return sorted(vals, key=int) if field == 'cwe' else sorted(vals)


def emit_group_table(out, run, field, title, arrow, a_arm, b_arm):
    out.append(f'### {title}\n')
    out.append(f'| {field.title()} | Cases | fix_quality | no_harm | Clean | Does not build |')
    out.append('|---|---|---|---|---|---|')
    for g in run.groups(field) + ['ALL']:
        eq = {} if g == 'ALL' else {field: g}
        a, b = run.sel(a_arm, **eq), run.sel(b_arm, **eq)
        if not a and not b:
            continue
        out.append(
            f'| {g} | {len(a)} '
            f'| {fmt(mean(a, "fix_quality"))} {arrow} {fmt(mean(b, "fix_quality"))} '
            f'| {fmt(mean(a, "no_harm"))} {arrow} {fmt(mean(b, "no_harm"))} '
            f'| {sum(1 for r in a if r["clean"])} {arrow} {sum(1 for r in b if r["clean"])} '
            f'| {sum(1 for r in a if r["status"] == "FAIL")} {arrow} '
            f'{sum(1 for r in b if r["status"] == "FAIL")} |')
    out.append('')


def emit_claims(out, run, a_arm, b_arm):
    """Every assertion a write-up tends to make about the per-language table, computed."""
    out.append('### Derived claims - copy these rather than reading them off the table\n')
    langs = run.groups('language')
    cells = []
    for lg in langs:
        n = len(run.sel(a_arm, language=lg))
        for axis in AXES:
            a, b = run.cell(a_arm, axis, language=lg), run.cell(b_arm, axis, language=lg)
            if a is None or b is None:
                continue
            cells.append(dict(lang=lg, axis=axis, a=a, b=b, d=b - a, n=n))
    if not cells:
        return
    down = sorted([c for c in cells if c['d'] < -0.005], key=lambda c: c['d'])
    up = [c for c in cells if c['d'] > 0.005]
    out.append(f'- per-language cells: {len(cells)} ({len(langs)} languages x {len(AXES)} axes)')
    out.append(f'- cells where guidance raises the score: {len(up)}; lowers it: {len(down)}; '
               f'unchanged: {len(cells) - len(up) - len(down)}')
    big = [c for c in down if c['d'] < -MATERIAL]
    small = [c for c in down if c['d'] >= -MATERIAL]
    out.append(f'- of the {len(down)} that decline, {len(big)} move by more than {MATERIAL:.2f} '
               f'and {len(small)} by less')
    for c in down:
        flags = []
        if c['a'] >= CEILING:
            flags.append(f'CEILING: unguided already {c["a"]:.2f}, can barely rise')
        if c['n'] < SMALL_N:
            flags.append(f'SMALL-N: {c["n"]} cases, read them before calling it noise')
        out.append(f"    {c['d']:+.2f}  {c['lang']:<11}{c['axis']:<12}{c['a']:.2f} -> {c['b']:.2f}"
                   f"  n={c['n']}" + ('   ' + '; '.join(flags) if flags else ''))
    tiny = [lg for lg in langs if len(run.sel(a_arm, language=lg)) < SMALL_N]
    if tiny:
        out.append(f'- languages under {SMALL_N} cases, where a mean is one or two write-ups: '
                   + ', '.join(f'{lg} ({len(run.sel(a_arm, language=lg))})' for lg in tiny))
    for axis in AXES:
        a_all, b_all = run.cell(a_arm, axis), run.cell(b_arm, axis)
        pair = {'B ahead': 0, 'A ahead': 0, 'tie': 0}
        by = {}
        for r in run.rows:
            by.setdefault(f"{r['cwe']}/{r['language']}/{r['case']}", {})[r['arm']] = r
        for d in by.values():
            if a_arm in d and b_arm in d and d[a_arm].get(axis) is not None:
                x, y = d[a_arm][axis], d[b_arm][axis]
                pair['B ahead' if y > x else 'A ahead' if x > y else 'tie'] += 1
        out.append(f'- {axis}: {fmt(a_all)} -> {fmt(b_all)} ({b_all - a_all:+.2f}); paired per case {pair}')
    for arm in (a_arm, b_arm):
        rs = run.sel(arm)
        out.append(f'- {arm}: clean {sum(1 for r in rs if r["clean"])}/{len(rs)}, '
                   f'build failures {sum(1 for r in rs if r["status"] == "FAIL")}, '
                   f'judge splits on no_harm {sum(1 for r in rs if r.get("spread_no_harm"))}')
    out.append('')


def emit_cross_run(out, runs, arrow, a_arm, b_arm):
    out.append('### Across runs\n')
    out.append(f'| Run | fix_quality | no_harm | Does not build |')
    out.append('|---|---|---|---|')
    for run in runs:
        a, b = run.sel(a_arm), run.sel(b_arm)
        out.append(f'| {run.label} | {fmt(mean(a, "fix_quality"))} {arrow} {fmt(mean(b, "fix_quality"))} '
                   f'| {fmt(mean(a, "no_harm"))} {arrow} {fmt(mean(b, "no_harm"))} '
                   f'| {sum(1 for r in a if r["status"] == "FAIL")} {arrow} '
                   f'{sum(1 for r in b if r["status"] == "FAIL")} |')
    out.append('')
    out.append('Per language, each run as its own pair of columns:\n')
    header = '| Language | Cases |' + ''.join(f' {r.label} fix_quality | {r.label} no_harm |' for r in runs)
    out.append(header)
    out.append('|---|---|' + '---|---|' * len(runs))
    for lg in runs[0].groups('language'):
        cells = ''
        for run in runs:
            for axis in AXES:
                cells += (f' {fmt(run.cell(a_arm, axis, language=lg))} {arrow} '
                          f'{fmt(run.cell(b_arm, axis, language=lg))} |')
        out.append(f'| {lg} | {len(runs[0].sel(a_arm, language=lg))} |{cells}')
    cells = ''
    for run in runs:
        for axis in AXES:
            cells += f' {fmt(run.cell(a_arm, axis))} {arrow} {fmt(run.cell(b_arm, axis))} |'
    out.append(f'| ALL | {len(runs[0].sel(a_arm))} |{cells}')
    out.append('')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('runs', nargs='*', help='run numbers, e.g. 20 21')
    ap.add_argument('--map', help='legacy: explicit arm-map path')
    ap.add_argument('--scores', help='legacy: explicit scores directory')
    ap.add_argument('--gate', help='explicit gate.json (single-run mode)')
    ap.add_argument('--label', action='append', default=[], help='label per run, in order')
    ap.add_argument('--arms', default='A,B', help='control,treatment arm labels (default A,B)')
    ap.add_argument('--arrow-unicode', action='store_true', help='use an arrow glyph, not ->')
    ap.add_argument('--out')
    args = ap.parse_args()
    arrow = '→' if args.arrow_unicode else '->'
    a_arm, b_arm = args.arms.split(',')

    loaded = []
    if args.map or args.scores:
        if not (args.map and args.scores):
            raise SystemExit('--map and --scores go together')
        rows, missing, nj = load_run(args.map, args.scores, args.gate)
        loaded.append(Run(rows, missing, nj, args.label[0] if args.label else 'run'))
    else:
        if not args.runs:
            raise SystemExit('give one or more run numbers, or --map with --scores')
        for i, n in enumerate(args.runs):
            m = os.path.join(REPO, f'arm-map-v{n}.json')
            s = os.path.join(REPO, f'scores-v{n}')
            g = args.gate if (args.gate and len(args.runs) == 1) else os.path.join(REPO, f'runs-v{n}', 'gate.json')
            if not os.path.exists(m):
                raise SystemExit(f'no {m}')
            rows, missing, nj = load_run(m, s, g)
            loaded.append(Run(rows, missing, nj, args.label[i] if i < len(args.label) else f'run {n}'))

    out = []
    for run in loaded:
        out.append(f'## {run.label}\n')
        out.append(f'- write-ups scored: {len(run.rows)}; judge files: {run.n_judge_files}; '
                   f'judges per write-up: {sorted({r["n_judges"] for r in run.rows})}')
        if run.missing:
            out.append(f'- MISSING SCORES ({len(run.missing)}): {", ".join(run.missing[:20])}')
        if any(r['status'] for r in run.rows):
            counts = {}
            for r in run.rows:
                counts[r['status'] or 'no gate'] = counts.get(r['status'] or 'no gate', 0) + 1
            out.append(f'- gate: {counts}')
        out.append('')
        emit_claims(out, run, a_arm, b_arm)
        for field, title in (('language', 'By language'), ('cwe', 'By CWE'), ('source', 'By case source')):
            if any(r.get(field) is not None for r in run.rows):
                emit_group_table(out, run, field, title, arrow, a_arm, b_arm)
    if len(loaded) > 1:
        emit_cross_run(out, loaded, arrow, a_arm, b_arm)

    text = '\n'.join(out) + '\n'
    if args.out:
        io.open(args.out, 'w', encoding='utf-8', newline='\n').write(text)
        print('written ->', args.out)
    else:
        print(text)


main()
