#!/usr/bin/env python3
"""Tier-2 type check: resolve every case fixture against a per-language superset environment.

parsecheck.py establishes that a fixture parses. This establishes that it resolves - every
import, method and overload against the real libraries. The fixtures carry no manifests, and they
do not need them: the third-party surface of each language across the whole corpus is a short
list, so one superset manifest per language resolves every case:

    java        stubs/java/pom.xml, resolved once with Maven into a classpath; javac --release 17
    csharp      stubs/csharp/superset.csproj (Web SDK plus the union of packages), restored once;
                dotnet build with the case's files as compile items, as a library first and as an
                executable when the case has top-level statements
    javascript  stubs/javascript/package.json, installed once; resolve-check.js loads every
                bare specifier from that node_modules, checks relative specifiers against the
                case directory, and checks destructured require() names against real exports
    go          stubs/go/go.mod; case files are copied into a package under the module and
                `go vet` type-checks them (a `func main` stub is added for main packages without one)
    python      stubs/python/requirements.txt in an isolated uv environment; mypy with untyped-
                library and annotation noise disabled, so what remains is unresolved names and
                members

Classes and modules a fixture references but does not ship (a repository, an entity, a test
harness, a config module) are compile-only stand-ins under stubs/<language>/shared and
stubs/<language>/cases/<cwe>/<lang>/<id>/. Arms never see stubs/; nothing here reaches a
write-up. Framework-hosted files that cannot exist outside their host (ASP.NET Web Forms, JSP,
Razor views) are reported as unchecked. C and C++ have no type check here.

Usage:
    python evals/scripts/compilecheck.py [--lang <language>] [--only <cwe>] [--paths <path>...] [--verbose]

Each language is skipped with a note when its toolchain is missing, so the hook never blocks a
commit on a machine without one; CI carries all of them. Exit 1 if any case fails.
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
STUBS = os.path.join(EVALS, 'stubs')
IS_WIN = os.name == 'nt'


def run(cmd, cwd=None, timeout=600, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           encoding='utf-8', errors='replace', env=env)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except FileNotFoundError:
        return None, f'{cmd[0]} not found'
    except subprocess.TimeoutExpired:
        return -1, 'timeout'


def sources(d, ext):
    if not os.path.isdir(d):
        return []
    return sorted(os.path.join(dp, f) for dp, _, fs in os.walk(d) for f in fs if f.endswith(ext))


def case_stub_dir(lang, key):
    return os.path.join(STUBS, lang, 'cases', *key.split('/'))


# ---------------------------------------------------------------- java
JAVA_STUBS = os.path.join(STUBS, 'java')
JAVA_CP_CACHE = os.path.join(JAVA_STUBS, 'classpath.txt')


def java_classpath():
    pom = os.path.join(JAVA_STUBS, 'pom.xml')
    if os.path.exists(JAVA_CP_CACHE) and os.path.getmtime(JAVA_CP_CACHE) >= os.path.getmtime(pom):
        return io.open(JAVA_CP_CACHE, encoding='utf-8').read().strip()
    mvn = shutil.which('mvn') or shutil.which('mvn.cmd')
    if not mvn:
        return None
    rc, out = run([mvn, '-q', '-B', 'dependency:build-classpath', f'-Dmdep.outputFile={JAVA_CP_CACHE}',
                   f'-Dmdep.pathSeparator={os.pathsep}'], cwd=JAVA_STUBS)
    if rc != 0 or not os.path.exists(JAVA_CP_CACHE):
        raise SystemExit('mvn dependency:build-classpath failed:\n' + out[-2000:])
    return io.open(JAVA_CP_CACHE, encoding='utf-8').read().strip()


class JavaChecker:
    lang = 'java'

    def __init__(self):
        self.ok = bool(shutil.which('javac'))
        self.note = 'javac not on PATH' if not self.ok else ''
        if self.ok:
            self.cp = java_classpath()
            if self.cp is None:
                self.ok, self.note = False, 'mvn not on PATH and no cached classpath'
            self.shared = sources(os.path.join(JAVA_STUBS, 'shared'), '.java')

    def check(self, case_dir, key):
        files = sources(case_dir, '.java')
        if not files:
            return 'UNCHECKED', 'no .java files (JSP)'
        extra = sources(case_stub_dir('java', key), '.java')
        with tempfile.TemporaryDirectory() as td:
            rc, out = run(['javac', '--release', '17', '-proc:none', '-Xmaxerrs', '20', '-cp', self.cp, '-d', td]
                          + self.shared + extra + files)
        if rc == 0:
            return 'OK', f'{len(extra)} case stub(s)' if extra else ''
        errs = [l.strip() for l in out.splitlines() if ' error: ' in l]
        return 'FAIL', (errs[0] if errs else out.strip())[:220]


# ---------------------------------------------------------------- csharp
CS_STUBS = os.path.join(STUBS, 'csharp')
CS_ERR = re.compile(r'error (CS\d{4}): ([^\[]*)')


class CSharpChecker:
    lang = 'csharp'

    def __init__(self):
        self.ok = bool(shutil.which('dotnet'))
        self.note = 'dotnet not on PATH' if not self.ok else ''
        if not self.ok:
            return
        self.template = io.open(os.path.join(CS_STUBS, 'superset.csproj'), encoding='utf-8').read()
        if not os.path.exists(os.path.join(CS_STUBS, 'obj', 'project.assets.json')):
            rc, out = run(['dotnet', 'restore', 'superset.csproj', '-nologo', '-v', 'q'], cwd=CS_STUBS)
            if rc != 0:
                raise SystemExit('dotnet restore of stubs/csharp/superset.csproj failed:\n' + out[-2000:])
        self.work = tempfile.mkdtemp(prefix='cwe-cs-')
        shutil.copytree(os.path.join(CS_STUBS, 'obj'), os.path.join(self.work, 'obj'))
        self.shared = sources(os.path.join(CS_STUBS, 'shared'), '.cs')

    def _build(self, files, output_type):
        items = '\n'.join(f'    <Compile Include="{f.replace(os.sep, "/")}" />' for f in files)
        proj = self.template.replace('    <!-- CASE_COMPILE_ITEMS -->', items)
        proj = proj.replace('<OutputType>Library</OutputType>', f'<OutputType>{output_type}</OutputType>')
        io.open(os.path.join(self.work, 'superset.csproj'), 'w', encoding='utf-8').write(proj)
        return run(['dotnet', 'build', 'superset.csproj', '--no-restore', '-nologo', '-v', 'q'], cwd=self.work)

    def check(self, case_dir, key):
        files = sources(case_dir, '.cs')
        if not files:
            return 'UNCHECKED', 'no .cs files'
        if any('using System.Web.UI' in io.open(f, encoding='utf-8', errors='replace').read() for f in files):
            return 'UNCHECKED', 'ASP.NET Web Forms (.NET Framework only)'
        extra = sources(case_stub_dir('csharp', key), '.cs')
        rc, out = self._build(self.shared + extra + files, 'Library')
        if rc != 0 and 'CS8805' in out:
            rc, out = self._build(self.shared + extra + files, 'Exe')
        if rc == 0:
            return 'OK', f'{len(extra)} case stub(s)' if extra else ''
        errs = sorted({f'{m.group(1)}: {m.group(2).strip()}' for m in CS_ERR.finditer(out)})
        return 'FAIL', (errs[0] if errs else out.strip())[:220]


# ---------------------------------------------------------------- javascript
JS_STUBS = os.path.join(STUBS, 'javascript')


class JsChecker:
    lang = 'javascript'

    def __init__(self):
        self.ok = bool(shutil.which('node'))
        self.note = 'node not on PATH' if not self.ok else ''
        if self.ok and not os.path.isdir(os.path.join(JS_STUBS, 'node_modules')):
            npm = shutil.which('npm') or shutil.which('npm.cmd')
            if not npm:
                self.ok, self.note = False, 'npm not on PATH and no node_modules'
                return
            rc, out = run([npm, 'install', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=JS_STUBS)
            if rc != 0:
                raise SystemExit('npm install in stubs/javascript failed:\n' + out[-2000:])

    def check(self, case_dir, key):
        files = sources(case_dir, '.js')
        if not files:
            return 'UNCHECKED', 'no .js files'
        rc, out = run(['node', os.path.join(JS_STUBS, 'resolve-check.js')] + files)
        lines = [l for l in out.splitlines() if l.startswith(('FAIL', 'UNCHECKED'))]
        fails = [l for l in lines if l.startswith('FAIL')]
        if fails:
            return 'FAIL', fails[0].split(': ', 1)[-1][:220]
        if lines:
            return 'UNCHECKED', lines[0].split(': ', 1)[-1][:220]
        return 'OK', ''


# ---------------------------------------------------------------- go
GO_STUBS = os.path.join(STUBS, 'go')


class GoChecker:
    lang = 'go'

    def __init__(self):
        self.ok = bool(shutil.which('go'))
        self.note = 'go not on PATH' if not self.ok else ''

    def check(self, case_dir, key):
        files = sources(case_dir, '.go')
        if not files:
            return 'UNCHECKED', 'no .go files'
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(os.path.join(GO_STUBS, 'go.mod'), td)
            shutil.copy(os.path.join(GO_STUBS, 'go.sum'), td)
            pkg = os.path.join(td, 'c')
            os.makedirs(pkg)
            texts = []
            for f in files:
                shutil.copy(f, pkg)
                texts.append(io.open(f, encoding='utf-8', errors='replace').read())
            for f in sources(case_stub_dir('go', key), '.go'):
                shutil.copy(f, pkg)
            if any(re.search(r'^package main\b', t, re.M) for t in texts) and not any('func main(' in t for t in texts):
                io.open(os.path.join(pkg, 'zz_main_stub.go'), 'w', encoding='utf-8').write('package main\n\nfunc main() {}\n')
            rc, out = run(['go', 'vet', './c'], cwd=td)
        if rc == 0:
            return 'OK', ''
        errs = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('#')]
        return 'FAIL', (errs[0] if errs else out.strip())[:220]


# ---------------------------------------------------------------- python
PY_STUBS = os.path.join(STUBS, 'python')
PY_REQ = os.path.join(PY_STUBS, 'requirements.txt')


class PythonChecker:
    lang = 'python'

    def __init__(self):
        self.uv = shutil.which('uv')
        self.ok = bool(self.uv)
        self.note = 'uv not on PATH' if not self.ok else ''

    def check(self, case_dir, key):
        files = sources(case_dir, '.py')
        if not files:
            return 'UNCHECKED', 'no .py files'
        env = dict(os.environ)
        env['MYPYPATH'] = case_stub_dir('python', key)
        flags = ['--follow-imports=silent', '--show-error-codes', '--no-error-summary', '--no-color-output',
                 '--disable-error-code', 'import-untyped', '--disable-error-code', 'var-annotated']
        relative = any(re.search(r'^from \.', io.open(f, encoding='utf-8', errors='replace').read(), re.M) for f in files)
        with tempfile.TemporaryDirectory() as td:
            if relative:
                # A Django-style app with `from . import views` is a package; give mypy one.
                pkg = os.path.join(td, 'casepkg')
                os.makedirs(pkg)
                for f in files:
                    shutil.copy(f, pkg)
                io.open(os.path.join(pkg, '__init__.py'), 'w').close()
                target = [pkg]
            else:
                target = files
            rc, out = run([self.uv, 'run', '--no-project', '--python', '3.13', '--with-requirements', PY_REQ,
                           'mypy'] + target + flags, env=env)
        errs = [l.strip() for l in out.splitlines() if ': error:' in l]
        if rc is None:
            return 'UNCHECKED', out
        if errs:
            return 'FAIL', errs[0][:220]
        if rc not in (0, 1):
            return 'UNCHECKED', out.strip().splitlines()[-1][:220] if out.strip() else f'mypy exit {rc}'
        return 'OK', ''


CHECKERS = {c.lang: c for c in (JavaChecker, CSharpChecker, JsChecker, GoChecker, PythonChecker)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lang')
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

    checkers = {}
    counts, failures = {}, []
    for cwe in sorted(os.listdir(CASES)):
        if args.only and cwe != args.only:
            continue
        for lang in sorted(os.listdir(os.path.join(CASES, cwe))):
            if args.lang and lang != args.lang:
                continue
            for cid in sorted(os.listdir(os.path.join(CASES, cwe, lang))):
                case_dir = os.path.join(CASES, cwe, lang, cid)
                if not os.path.exists(os.path.join(case_dir, 'case.json')):
                    continue
                key = f'{cwe}/{lang}/{cid}'
                if wanted is not None and key not in wanted:
                    continue
                if lang not in CHECKERS:
                    status, detail = 'UNCHECKED', f'no type check for {lang}'
                else:
                    if lang not in checkers:
                        checkers[lang] = CHECKERS[lang]()
                    chk = checkers[lang]
                    if not chk.ok:
                        status, detail = 'UNCHECKED', chk.note
                    else:
                        status, detail = chk.check(case_dir, key)
                counts.setdefault(lang, {}).setdefault(status, 0)
                counts[lang][status] += 1
                if status == 'FAIL':
                    failures.append((key, detail))
                if args.verbose or status != 'OK':
                    print(f'{status:9s} {key}: {detail}')
    print('\nsummary:')
    for lang in sorted(counts):
        print(f'  {lang:11s} ' + ', '.join(f'{k} {v}' for k, v in sorted(counts[lang].items())))
    print(f'{len(failures)} failing')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
