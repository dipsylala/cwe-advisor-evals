#!/usr/bin/env python3
"""Deterministic collection and validation for arm outputs and judge scores.

Every run so far has needed the same hand-work after the agents finish: outputs written one
directory too deep, empty directories left by a mkdir on the file path, scratch files dropped next
to the write-up, a judge file with a key missing, and a workflow tally that undercounts the disk.
This script does that work mechanically and prints the done-set the workflow scripts take as
`args`, so a run interrupted by the session limit is resumed from what is actually on disk.

Usage:
    python evals/scripts/collect.py mkdirs <run-dir>/<arm>
        Create <cwe>/<language>/ under the arm directory for every case, so agents never have
        to create anything and cannot mkdir the file path by mistake.

    python evals/scripts/collect.py arm <run-dir>/<arm> [--out done.json]
        Flatten <id>/<id>.md to <id>.md, delete empty directories, report and remove non-.md
        files, check every write-up carries the required headings, and compare the set of
        write-ups against the corpus. Prints the done-set (cwe/language/id keys present) and the
        missing list. A nested file is moved only when no flat file exists; if both exist and
        differ, both are kept and reported - that needs a human.

    python evals/scripts/collect.py judges <scores-dir> (--total N [--seg 40] | --index index.json) [--out done.json]
        Check every judge-s<idx>-<j>.json parses and carries exactly its segment's run ids, each
        with fix_quality and no_harm. Segments are either fixed-size (--total/--seg, the layout
        runs 8-16 used) or taken from a bundle index (see bundle.py). Prints the done-set of
        valid s<idx>-<j> keys and the list of missing or invalid ones.
"""
import argparse
import io
import json
import os
import re
import shutil
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CASES = os.path.join(REPO, 'evals', 'cases')
REQUIRED = ('## Verdict', '## Source', '## Fix', '## Explanation')


def case_keys():
    keys = []
    for cwe in sorted(os.listdir(CASES)):
        for lang in sorted(os.listdir(os.path.join(CASES, cwe))):
            for cid in sorted(os.listdir(os.path.join(CASES, cwe, lang))):
                if os.path.exists(os.path.join(CASES, cwe, lang, cid, 'case.json')):
                    keys.append((cwe, lang, cid))
    return keys


def cmd_mkdirs(args):
    n = 0
    for cwe, lang, _ in case_keys():
        d = os.path.join(args.arm_dir, cwe, lang)
        if not os.path.isdir(d):
            os.makedirs(d)
            n += 1
    print(f'{n} directories created under {args.arm_dir}')


def cmd_arm(args):
    root = args.arm_dir
    moved, removed_dirs, removed_files, conflicts, bad_headings = 0, 0, [], [], []
    # 1. flatten nested <id>/<id>.md and remove scratch files
    for cwe in sorted(os.listdir(root)):
        cwe_dir = os.path.join(root, cwe)
        if not os.path.isdir(cwe_dir):
            removed_files.append(os.path.relpath(cwe_dir, root))
            os.remove(cwe_dir)
            continue
        for lang in sorted(os.listdir(cwe_dir)):
            lang_dir = os.path.join(cwe_dir, lang)
            if not os.path.isdir(lang_dir):
                removed_files.append(os.path.relpath(lang_dir, root))
                os.remove(lang_dir)
                continue
            for entry in sorted(os.listdir(lang_dir)):
                p = os.path.join(lang_dir, entry)
                if os.path.isdir(p):
                    nested = os.path.join(p, entry + '.md')
                    flat = os.path.join(lang_dir, entry + '.md')
                    if os.path.exists(nested):
                        if not os.path.exists(flat):
                            shutil.move(nested, flat)
                            moved += 1
                        elif io.open(nested, 'rb').read() == io.open(flat, 'rb').read():
                            os.remove(nested)
                        else:
                            conflicts.append(os.path.relpath(p, root))
                            continue
                    for other in os.listdir(p):
                        op = os.path.join(p, other)
                        if os.path.isdir(op):
                            shutil.rmtree(op)
                        else:
                            os.remove(op)
                        removed_files.append(os.path.relpath(op, root))
                    if not os.listdir(p):
                        os.rmdir(p)
                        removed_dirs += 1
                elif not entry.endswith('.md'):
                    removed_files.append(os.path.relpath(p, root))
                    os.remove(p)
    # 2. compare against the corpus and check headings
    present = set()
    for cwe, lang, cid in case_keys():
        f = os.path.join(root, cwe, lang, cid + '.md')
        if os.path.exists(f):
            present.add(f'{cwe}/{lang}/{cid}')
            text = io.open(f, encoding='utf-8', errors='replace').read()
            missing = [h for h in REQUIRED if not re.search(r'(?m)^' + re.escape(h) + r'\b', text)]
            if missing:
                bad_headings.append((f'{cwe}/{lang}/{cid}', missing))
    expected = {f'{c}/{l}/{i}' for c, l, i in case_keys()}
    extra = set()
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if fn.endswith('.md'):
                rel = os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, '/')[:-3]
                if rel not in expected:
                    extra.add(rel)
    missing_cases = sorted(expected - present)
    print(f'{root}: {len(present)} of {len(expected)} write-ups present')
    print(f'flattened {moved}, removed {removed_dirs} empty dirs, removed {len(removed_files)} stray files')
    for x in removed_files:
        print('  removed:', x)
    for c in conflicts:
        print('  CONFLICT (nested and flat differ, both kept):', c)
    for k, m in bad_headings:
        print(f'  headings missing in {k}: {", ".join(m)}')
    for x in sorted(extra):
        print('  not a case (leave or remove by hand):', x)
    if missing_cases:
        print(f'missing {len(missing_cases)}:')
        for m in missing_cases:
            print('  ', m)
    done = sorted(present)
    if args.out:
        io.open(args.out, 'w', encoding='utf-8', newline='\n').write(json.dumps(done) + '\n')
        print('done-set ->', args.out)
    return 0 if not missing_cases and not conflicts else 1


def cmd_judges(args):
    if args.index:
        index = json.loads(io.open(args.index, encoding='utf-8').read())
        segments = {int(s['idx']): set(s['rids']) for s in index}
    else:
        segments = {}
        idx = 0
        for start in range(101, 101 + args.total, args.seg):
            end = min(start + args.seg - 1, 100 + args.total)
            segments[idx] = {f'R{n}' for n in range(start, end + 1)}
            idx += 1
    valid, problems = [], []
    for idx, want in sorted(segments.items()):
        for j in range(1, args.judges + 1):
            key = f's{idx}-{j}'
            f = os.path.join(args.scores_dir, f'judge-{key}.json')
            if not os.path.exists(f):
                problems.append((key, 'missing'))
                continue
            try:
                d = json.loads(io.open(f, encoding='utf-8').read())
            except Exception as e:  # noqa: BLE001
                problems.append((key, f'unparseable: {str(e)[:60]}'))
                continue
            if not isinstance(d, dict) or set(d) != want:
                problems.append((key, f'{len(d) if isinstance(d, dict) else "?"} keys, expected {len(want)}'))
                continue
            bad = [r for r in want if not (isinstance(d[r], dict)
                                           and d[r].get('fix_quality') in (0, 1, 2)
                                           and d[r].get('no_harm') in (0, 1, 2))]
            if bad:
                problems.append((key, f'{len(bad)} entries lack an integer 0-2 fix_quality/no_harm: {bad[:3]}'))
                continue
            valid.append(key)
    total = len(segments) * args.judges
    print(f'{args.scores_dir}: {len(valid)} of {total} judge files valid')
    for key, why in problems:
        print(f'  {key}: {why}')
    if args.out:
        io.open(args.out, 'w', encoding='utf-8', newline='\n').write(json.dumps(valid) + '\n')
        print('done-set ->', args.out)
    else:
        print('done-set:', json.dumps(valid))
    return 0 if not problems else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('mkdirs')
    p.add_argument('arm_dir')
    p = sub.add_parser('arm')
    p.add_argument('arm_dir')
    p.add_argument('--out')
    p = sub.add_parser('judges')
    p.add_argument('scores_dir')
    p.add_argument('--total', type=int)
    p.add_argument('--seg', type=int, default=40)
    p.add_argument('--index')
    p.add_argument('--judges', type=int, default=3)
    p.add_argument('--out')
    args = ap.parse_args()
    if args.cmd == 'judges' and not (args.total or args.index):
        ap.error('judges needs --total or --index')
    return {'mkdirs': cmd_mkdirs, 'arm': cmd_arm, 'judges': cmd_judges}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
