#!/usr/bin/env python3
"""Pack blinded write-ups and their case files into judge bundles.

Runs 8-16 handed each judge a list of 40 blinded files and let it discover and read the case
files itself. Measured on run 16, the median judge agent took 31 turns and re-sent about 120k
tokens of context on each - the write-ups are a small part of that; the turns are the cost. A
bundle puts everything a judge needs for a segment into one file it reads once: each blinded
write-up followed by the complete contents of its case directory, minus case.json (which holds
the answer) and anything that is not source. Nothing in a bundle names an arm.

Segments are packed by size, not count, so every bundle fits in one Read: --max-bytes bounds
the bundle and the packer fills each segment in pool order until the next item would overflow.
The index records which run ids are in which segment; collect.py's `judges --index` validates
judge files against it.

Usage:
    python evals/scripts/bundle.py <blind-dir> --out <bundle-dir> [--max-bytes 80000] [--rids R221-R260]

Writes <bundle-dir>/s<idx>.md and <bundle-dir>/index.json.
"""
import argparse
import io
import json
import os
import re
import shutil

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CASE_DIR_RE = re.compile(r'^Case directory: `([^`]+)/`', re.M)
SKIP_NAMES = {'case.json', '__pycache__', '.DS_Store'}
SKIP_EXT = {'.pyc', '.class', '.o', '.obj', '.exe', '.dll', '.jar', '.png', '.jpg', '.gif', '.zip'}


def case_files(case_dir):
    out = []
    for dp, dns, fns in os.walk(os.path.join(REPO, case_dir)):
        dns[:] = sorted(d for d in dns if d not in SKIP_NAMES)
        for fn in sorted(fns):
            if fn in SKIP_NAMES or os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, os.path.join(REPO, case_dir)).replace(os.sep, '/')
            out.append((rel, io.open(p, encoding='utf-8', errors='replace').read()))
    return out


def item_text(rid, body):
    m = CASE_DIR_RE.search(body)
    if not m:
        raise SystemExit(f'{rid}: no "Case directory:" line in header')
    case_dir = m.group(1)
    parts = [f'\n\n======================== {rid} ========================\n\n', body.rstrip(), '\n\n',
             f'-------- case files for {rid} ({case_dir}/) --------\n']
    for rel, text in case_files(case_dir):
        parts.append(f'\n===== FILE: {case_dir}/{rel} =====\n{text.rstrip()}\n===== END FILE =====\n')
    return ''.join(parts)


def rid_num(name):
    return int(name[1:-3])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('blind_dir')
    ap.add_argument('--out', required=True)
    ap.add_argument('--max-bytes', type=int, default=80000)
    ap.add_argument('--rids', help='inclusive range like R221-R260 to bundle only part of a pool')
    args = ap.parse_args()

    names = sorted((f for f in os.listdir(args.blind_dir) if re.fullmatch(r'R\d+\.md', f)), key=rid_num)
    if args.rids:
        lo, hi = (int(x[1:]) for x in args.rids.split('-'))
        names = [n for n in names if lo <= rid_num(n) <= hi]
    shutil.rmtree(args.out, ignore_errors=True)
    os.makedirs(args.out)

    segments = []
    cur, cur_bytes = [], 0
    oversize = []
    for n in names:
        rid = n[:-3]
        text = item_text(rid, io.open(os.path.join(args.blind_dir, n), encoding='utf-8').read())
        b = len(text.encode('utf-8'))
        if b > args.max_bytes:
            oversize.append((rid, b))
        if cur and cur_bytes + b > args.max_bytes:
            segments.append(cur)
            cur, cur_bytes = [], 0
        cur.append((rid, text, b))
        cur_bytes += b
    if cur:
        segments.append(cur)

    index = []
    for idx, seg in enumerate(segments):
        path = os.path.join(args.out, f's{idx}.md')
        head = (f'# Segment s{idx}: {len(seg)} write-ups ({", ".join(r for r, _, _ in seg)})\n\n'
                'Each write-up is followed by the complete contents of its case directory. '
                'Score every write-up listed above.\n')
        io.open(path, 'w', encoding='utf-8', newline='\n').write(head + ''.join(t for _, t, _ in seg))
        index.append({'idx': idx, 'rids': [r for r, _, _ in seg], 'bytes': sum(b for _, _, b in seg)})
    io.open(os.path.join(args.out, 'index.json'), 'w', encoding='utf-8', newline='\n').write(
        json.dumps(index, indent=1) + '\n')

    sizes = [s['bytes'] for s in index]
    counts = [len(s['rids']) for s in index]
    print(f'{len(names)} write-ups -> {len(index)} segments in {args.out}')
    print(f'write-ups per segment: min {min(counts)} median {sorted(counts)[len(counts)//2]} max {max(counts)}')
    print(f'bytes per segment: min {min(sizes)} median {sorted(sizes)[len(sizes)//2]} max {max(sizes)}')
    for rid, b in oversize:
        print(f'  WARNING {rid} alone is {b} bytes, over --max-bytes; it has its own segment')


if __name__ == '__main__':
    main()
