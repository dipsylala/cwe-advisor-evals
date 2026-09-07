#!/usr/bin/env python3
"""Tier-2 type check: compile case fixtures against a per-language superset classpath and stubs.

parsecheck.py establishes that a fixture parses. This establishes that it resolves: every import,
every method, every overload, against the real libraries. The fixtures carry no manifests, and
they do not need them - the third-party surface across all Java cases is about twenty artifacts,
so one superset classpath (stubs/java/pom.xml) resolves every case. Classes a fixture references
but does not ship (a repository, an entity, a test harness) are compile-only stand-ins under
stubs/java/shared (Juliet's testcasesupport, the OWASP Benchmark helpers) and
stubs/java/cases/<cwe>/<lang>/<id>/. Arms never see stubs/; nothing here can reach a write-up.

Java only for now. The same shape - one superset manifest per language plus stubs - is the plan
for C# (a .csproj with the union of packages), JavaScript (one package.json), Go (one go.mod) and
Python (one requirements file with a type checker).

Usage:
    python evals/scripts/compilecheck.py [--only <cwe>] [--paths <path>...] [--verbose]

Needs javac and mvn on PATH. The classpath is resolved once with Maven and cached next to the pom
(stubs/java/classpath.txt, ignored by git); delete it to re-resolve after editing the pom.
Compiles with --release 17: the fixtures are javax-era, and JDK 25+ adds java.io.IO, which makes
the Juliet files' wildcard imports ambiguous on a newer release. Exit 1 if any case fails.
"""
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

EVALS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(EVALS)
CASES = os.path.join(EVALS, 'cases')
JAVA_STUBS = os.path.join(EVALS, 'stubs', 'java')
POM = os.path.join(JAVA_STUBS, 'pom.xml')
CP_CACHE = os.path.join(JAVA_STUBS, 'classpath.txt')


def java_classpath():
    if os.path.exists(CP_CACHE) and os.path.getmtime(CP_CACHE) >= os.path.getmtime(POM):
        return io.open(CP_CACHE, encoding='utf-8').read().strip()
    mvn = shutil.which('mvn') or shutil.which('mvn.cmd')
    if not mvn:
        return None
    sep = ';' if os.name == 'nt' else ':'
    p = subprocess.run([mvn, '-q', '-B', 'dependency:build-classpath', f'-Dmdep.outputFile={CP_CACHE}',
                        f'-Dmdep.pathSeparator={sep}'], cwd=JAVA_STUBS, capture_output=True, text=True)
    if p.returncode != 0 or not os.path.exists(CP_CACHE):
        raise SystemExit('mvn dependency:build-classpath failed:\n' + (p.stdout + p.stderr)[-2000:])
    return io.open(CP_CACHE, encoding='utf-8').read().strip()


def java_sources(d):
    return sorted(os.path.join(dp, f) for dp, _, fs in os.walk(d) for f in fs if f.endswith('.java'))


def check_java(case_dir, key, cp, shared):
    files = java_sources(case_dir)
    if not files:
        return 'UNCHECKED', 'no .java files'
    extra = java_sources(os.path.join(JAVA_STUBS, 'cases', *key.split('/')))
    with tempfile.TemporaryDirectory() as td:
        cmd = ['javac', '--release', '17', '-proc:none', '-Xmaxerrs', '20', '-cp', cp, '-d', td] + shared + extra + files
        p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if p.returncode == 0:
        return 'OK', f'{len(extra)} case stub(s)' if extra else ''
    errs = [l.strip() for l in (p.stdout + p.stderr).splitlines() if ' error: ' in l]
    return 'FAIL', (errs[0] if errs else (p.stdout + p.stderr).strip())[:220]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    ap.add_argument('--paths', nargs='*')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    wanted = None
    if args.paths is not None:
        wanted = set()
        for p in args.paths:
            ap_ = os.path.abspath(p) if os.path.isabs(p) else (
                os.path.abspath(os.path.join(EVALS, p)) if os.path.exists(os.path.join(EVALS, p))
                else os.path.abspath(os.path.join(REPO, p)))
            rel = os.path.relpath(ap_, CASES).replace(os.sep, '/')
            parts = rel.split('/')
            if not rel.startswith('..') and len(parts) >= 3:
                wanted.add('/'.join(parts[:3]))
        if not wanted:
            print('no case paths among the given paths; nothing to check')
            return 0

    if not shutil.which('javac'):
        print('javac not on PATH; nothing checked')
        return 0
    cp = java_classpath()
    if cp is None:
        print('mvn not on PATH and no cached classpath; java type check skipped (CI runs it)')
        return 0
    shared = java_sources(os.path.join(JAVA_STUBS, 'shared'))

    counts, failures = {}, []
    for cwe in sorted(os.listdir(CASES)):
        if args.only and cwe != args.only:
            continue
        for lang in sorted(os.listdir(os.path.join(CASES, cwe))):
            if lang != 'java':
                continue
            for cid in sorted(os.listdir(os.path.join(CASES, cwe, lang))):
                case_dir = os.path.join(CASES, cwe, lang, cid)
                if not os.path.exists(os.path.join(case_dir, 'case.json')):
                    continue
                key = f'{cwe}/{lang}/{cid}'
                if wanted is not None and key not in wanted:
                    continue
                status, detail = check_java(case_dir, key, cp, shared)
                counts[status] = counts.get(status, 0) + 1
                if status == 'FAIL':
                    failures.append((key, detail))
                if args.verbose or status != 'OK':
                    print(f'{status:9s} {key}: {detail}')
    print('summary (java):', ', '.join(f'{k} {v}' for k, v in sorted(counts.items())))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
