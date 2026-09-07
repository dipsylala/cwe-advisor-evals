#!/usr/bin/env python3
"""Compile gate for arm write-ups: apply each write-up's files to a copy of its case and type-check.

From run 17 a write-up's `## Fix` section carries the complete contents of every file the fix
changes or adds, one fenced block per file under a `### File: <path>` heading (HARNESS.md Step 2).
This script extracts those files, lays them over a scratch copy of the case directory, and runs
the same per-language check the fixtures themselves pass (compilecheck.py; perl -c for Perl).
The result is a mechanical, deterministic reading of "would this fix build" that costs no judge
tokens - the slip bucket runs 13-16 traced most guided losses to (an invented method, a missing
import, a package that does not exist) is exactly what this catches.

Statuses per write-up:

    OK          the case with the fix applied resolves
    FAIL        it does not; the note carries the first error
    UNCHECKED   no checker for this case (Web Forms, JSP, Blazor, a native binding, or the
                toolchain is missing on this machine)
    NO_FILES    the Fix section carries no `### File:` block - the write-up did not follow the
                format, so nothing can be applied
    BAD_FORMAT  a File block is unusable: a path outside the case directory, or an unterminated
                fence

The gate reads case.json (it is a script, not an arm or a judge) only to record whether the file
the finding names is among the files the write-up changed.

Usage:
    python evals/scripts/fixgate.py <run-dir>/<arm> [<run-dir>/<arm> ...] [--out gate.json]
                                    [--lang <language>] [--only <cwe>] [--verbose]

Prints a per-arm, per-language summary. --out writes one JSON object keyed
"<arm>/<cwe>/<language>/<id>" with status, note, the files applied, which of them differ from
the fixture, and whether the finding's file is among them.
"""
import argparse
import io
import json
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compilecheck  # noqa: E402
import gatekinds  # noqa: E402
import parsecheck  # noqa: E402

EVALS = compilecheck.EVALS
CASES = compilecheck.CASES

SECTION = re.compile(r'^## ', re.M)
FIX_HEADING = re.compile(r'^## Fix\b.*$', re.M)
FILE_HEADING = re.compile(r'^#{2,5}\s*File:\s*(.+?)\s*$', re.I | re.M)
FENCE_OPEN = re.compile(r'^ {0,3}(`{3,}|~{3,})')
SKIP_COPY = shutil.ignore_patterns('case.json', '__pycache__', '*.pyc')
# What each language's check actually compiles. A changed file outside this set (a Razor view,
# a JSP, a template, a config) is applied but not checked, and the note says so.
COMPILED_EXT = {'java': ('.java',), 'csharp': ('.cs',), 'javascript': ('.js',), 'go': ('.go',),
                'python': ('.py',), 'php': ('.php',), 'c': ('.c', '.h'), 'cpp': ('.cpp', '.cc', '.hpp', '.h'),
                'perl': ('.pl', '.pm')}


def fix_section(text):
    m = FIX_HEADING.search(text)
    if not m:
        return None
    rest = text[m.end():]
    n = SECTION.search(rest)
    return rest[:n.start()] if n else rest


def clean_path(raw, cwe, lang, cid):
    p = raw.strip().strip('`"\'').strip()
    p = p.replace('\\', '/')
    for prefix in (f'evals/cases/{cwe}/{lang}/{cid}/', f'cases/{cwe}/{lang}/{cid}/', f'{cid}/'):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    else:
        abs_case = os.path.abspath(os.path.join(CASES, cwe, lang, cid)).replace('\\', '/') + '/'
        if p.lower().startswith(abs_case.lower()):
            p = p[len(abs_case):]
    while p.startswith('./'):
        p = p[2:]
    if not p or p.startswith('/') or re.match(r'^[A-Za-z]:', p) or '..' in p.split('/'):
        return None
    return p


def extract_files(section, cwe, lang, cid):
    """Return ({path: content}, problems). Each `### File:` heading is followed by one fenced
    block holding the complete file; anything between the heading and the fence is ignored."""
    files, problems = {}, []
    heads = list(FILE_HEADING.finditer(section))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(section)
        chunk = section[h.end():end]
        path = clean_path(h.group(1), cwe, lang, cid)
        if path is None:
            problems.append(f'path outside the case directory: {h.group(1).strip()}')
            continue
        lines = chunk.split('\n')
        body, fence, start = None, None, None
        for j, line in enumerate(lines):
            if fence is None:
                fm = FENCE_OPEN.match(line)
                if fm:
                    fence, start = fm.group(1), j + 1
                continue
            if re.match(r'^ {0,3}' + re.escape(fence[0]) + '{' + str(len(fence)) + r',}\s*$', line):
                body = '\n'.join(lines[start:j])
                break
        if fence is None:
            problems.append(f'no fenced block after File heading for {path}')
            continue
        if body is None:
            problems.append(f'unterminated fence for {path}')
            continue
        if path in files:
            problems.append(f'{path} given twice; last one applied')
        files[path] = body if body.endswith('\n') else body + '\n'
    return files, problems


def read_finding_file(case_dir):
    meta = os.path.join(case_dir, 'case.json')
    try:
        return json.loads(io.open(meta, encoding='utf-8').read())['finding']['file'].replace('\\', '/')
    except (OSError, KeyError, ValueError):
        return None


class Gate:
    def __init__(self):
        self.checkers = {}

    def checker(self, lang):
        if lang not in self.checkers:
            if lang == 'perl':
                ok = bool(shutil.which('perl'))
                self.checkers[lang] = ('perl', ok, 'perl not on PATH')
            elif lang in compilecheck.CHECKERS:
                c = compilecheck.CHECKERS[lang]()
                self.checkers[lang] = (c, c.ok, c.note)
            else:
                self.checkers[lang] = (None, False, f'no checker for {lang}')
        return self.checkers[lang]

    def run_check(self, lang, key, scratch_case):
        chk, ok, note = self.checker(lang)
        if not ok:
            return 'UNCHECKED', note
        if lang == 'perl':
            files = compilecheck.sources(scratch_case, '.pl') + compilecheck.sources(scratch_case, '.pm')
            if not files:
                return 'UNCHECKED', 'no perl files'
            return parsecheck.check_perl(files, scratch_case)
        return chk.check(scratch_case, key)

    def gate(self, arm_dir, cwe, lang, cid):
        key = f'{cwe}/{lang}/{cid}'
        case_dir = os.path.join(CASES, cwe, lang, cid)
        text = io.open(os.path.join(arm_dir, cwe, lang, cid + '.md'), encoding='utf-8', errors='replace').read()
        rec = {'arm': os.path.basename(os.path.normpath(arm_dir)), 'cwe': cwe, 'language': lang, 'id': cid,
               'files': [], 'changed': [], 'new': [], 'finding_file_changed': False}
        section = fix_section(text)
        if section is None:
            rec.update(status='NO_FILES', note='no ## Fix section')
            return rec
        files, problems = extract_files(section, cwe, lang, cid)
        if problems and not files:
            rec.update(status='BAD_FORMAT', note='; '.join(problems)[:220])
            return rec
        if not files:
            rec.update(status='NO_FILES', note='no `### File:` block in ## Fix')
            return rec
        finding_file = read_finding_file(case_dir)
        rec['files'] = sorted(files)
        for p, content in files.items():
            orig = os.path.join(case_dir, p)
            if not os.path.exists(orig):
                rec['new'].append(p)
                rec['changed'].append(p)
            elif io.open(orig, encoding='utf-8', errors='replace', newline='').read().replace('\r\n', '\n') != content:
                rec['changed'].append(p)
        rec['finding_file_changed'] = finding_file in rec['changed']
        # The scratch copy keeps the cases/<cwe>/<lang>/<id> tail: the JavaScript resolver and the
        # PHP checker locate a case's stub mirror from that path shape.
        with tempfile.TemporaryDirectory(prefix='cwe-gate-') as td:
            scratch = os.path.join(td, 'cases', cwe, lang, cid)
            shutil.copytree(case_dir, scratch, ignore=SKIP_COPY)
            for p, content in files.items():
                dest = os.path.join(scratch, *p.split('/'))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                io.open(dest, 'w', encoding='utf-8', newline='\n').write(content)
            status, note = self.run_check(lang, key, scratch)
            note = note.replace(scratch + os.sep, '').replace(scratch, '')
        uncompiled = [p for p in rec['changed']
                      if not p.lower().endswith(COMPILED_EXT.get(lang, ())) or p.lower().endswith('.blade.php')]
        if uncompiled and status == 'OK':
            if len(uncompiled) == len(rec['changed']):
                status, note = 'UNCHECKED', 'no compiled file changed: ' + ', '.join(uncompiled)
            else:
                note = ('not compiled: ' + ', '.join(uncompiled) + ('; ' + note if note else ''))[:220]
        if problems:
            note = ('; '.join(problems) + ('; ' + note if note else ''))[:220]
        rec.update(status=status, note=note)
        rec['kind'], rec['kind_detail'] = gatekinds.classify(lang, status, note)
        return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('arm_dirs', nargs='+')
    ap.add_argument('--out')
    ap.add_argument('--lang')
    ap.add_argument('--only')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    gate = Gate()
    results = {}
    for arm_dir in args.arm_dirs:
        arm = os.path.basename(os.path.normpath(arm_dir))
        for cwe in sorted(os.listdir(CASES)):
            if args.only and cwe != args.only:
                continue
            for lang in sorted(os.listdir(os.path.join(CASES, cwe))):
                if args.lang and lang != args.lang:
                    continue
                for cid in sorted(os.listdir(os.path.join(CASES, cwe, lang))):
                    if not os.path.exists(os.path.join(CASES, cwe, lang, cid, 'case.json')):
                        continue
                    if not os.path.exists(os.path.join(arm_dir, cwe, lang, cid + '.md')):
                        continue
                    rec = gate.gate(arm_dir, cwe, lang, cid)
                    results[f'{arm}/{cwe}/{lang}/{cid}'] = rec
                    if args.verbose or rec['status'] not in ('OK',):
                        print(f"{rec['status']:<10} {arm}/{cwe}/{lang}/{cid}  {rec['note']}", flush=True)

    statuses = ('OK', 'FAIL', 'UNCHECKED', 'NO_FILES', 'BAD_FORMAT')
    print()
    print(f"{'arm':<8}{'language':<12}" + ''.join(f'{s:>11}' for s in statuses) + f"{'sink file':>11}")
    for arm in sorted({r['arm'] for r in results.values()}):
        langs = sorted({r['language'] for r in results.values() if r['arm'] == arm})
        for lang in langs + ['all']:
            rows = [r for r in results.values() if r['arm'] == arm and (lang == 'all' or r['language'] == lang)]
            counts = ''.join(f"{sum(1 for r in rows if r['status'] == s):>11}" for s in statuses)
            sink = sum(1 for r in rows if r['finding_file_changed'])
            print(f'{arm:<8}{lang:<12}{counts}{sink:>11}')
    for lang, (_, ok, note) in sorted(gate.checkers.items()):
        if not ok:
            print(f'note: {lang} unchecked - {note}')
    if args.out:
        io.open(args.out, 'w', encoding='utf-8', newline='\n').write(json.dumps(results, indent=1) + '\n')
        print('results ->', args.out)


if __name__ == '__main__':
    main()
