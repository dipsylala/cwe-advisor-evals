#!/usr/bin/env python3
"""Tier-1 syntax check of every case fixture, by language, with the toolchains on this machine.

The fixtures are source snippets with no build manifests, so nothing here resolves dependencies.
What it can establish is that every file parses: a fixture that does not parse as shipped cannot
be judged by compiling a fix against it, and a compile gate on arm output needs this as its floor.

Per language:
    php         php -l
    javascript  V8 parse as script then module (stubs/javascript/parse-check.js; `node --check`
                passes any file Node detects as ESM); JSX reported unchecked
    python      py_compile under this interpreter
    go          gofmt -e (parse only)
    perl        perl -c with stubs/perl/lib on @INC (a compile-only CGI.pm) and the case directory
                for its own .pm files, so the whole file compiles rather than stopping at the
                first module perl -c cannot load
    java        javac on the case directory with no classpath; an error is a syntax failure unless
                it is a resolution error ("package X does not exist", "cannot find symbol", and the
                "does not override a method from a supertype" that an unresolved superclass causes)
    csharp      dotnet build of a generated Microsoft.NET.Sdk.Web project over the case directory
                (BCL and ASP.NET Core resolve; NuGet packages do not); only diagnostics in an
                explicit list of Roslyn parser codes count as syntax failures
    c, cpp      unchecked unless gcc/clang/cl is on PATH; then -fsyntax-only
    jsp, razor, cshtml, html   unchecked (framework-hosted templates)

Usage:
    python evals/scripts/parsecheck.py [--only <cwe>] [--lang <language>] [--verbose]
    python evals/scripts/parsecheck.py --paths <path>... [--verbose]

--paths takes files or directories (repo-relative or absolute) and checks only the cases they fall
under - the pre-commit hook passes the staged paths. Prints one line per failing or unchecked case
and a summary. Exit 1 if any case fails.
"""
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Resolved from the script's own location so the sweep works in a standalone checkout of the evals
# repo (CI) as well as inside the cwe-advisor submodule, whatever the directory is called.
EVALS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(EVALS)
CASES = os.path.join(EVALS, 'cases')

JAVA_RESOLUTION = re.compile(r'error: (cannot find symbol|package [\w.]+ does not exist'
                             r'|static import only from classes and interfaces'
                             r'|method does not override or implement a method from a supertype'
                             r'|.+ in [\w.]+ does not override or implement a method from a supertype)')
# Roslyn parser diagnostics. Resolution errors also live in the CS1xxx range (CS1061 member not
# found, CS1069 type forwarded to a missing assembly), so the set is explicit rather than a range.
CS_SYNTAX_CODES = {
    'CS1001', 'CS1002', 'CS1003', 'CS1004', 'CS1007', 'CS1010', 'CS1012', 'CS1019', 'CS1022',
    'CS1023', 'CS1026', 'CS1028', 'CS1031', 'CS1035', 'CS1037', 'CS1041', 'CS1055', 'CS1073',
    'CS1513', 'CS1514', 'CS1519', 'CS1520', 'CS1525', 'CS1526', 'CS1528', 'CS1529', 'CS1576',
    'CS1585', 'CS1586', 'CS1597', 'CS1609', 'CS1611', 'CS1641', 'CS1644', 'CS1646', 'CS1733',
    'CS8124', 'CS8180', 'CS8641', 'CS8652', 'CS8803', 'CS8805',
}
CS_ANY = re.compile(r'error (CS\d{4}):')


def run(cmd, cwd=None, timeout=120):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except FileNotFoundError:
        return None, f'{cmd[0]} not found'
    except subprocess.TimeoutExpired:
        return -1, 'timeout'


def first_line(text, pat=None):
    for line in text.splitlines():
        if line.strip() and (pat is None or pat.search(line)):
            return line.strip()[:200]
    return text.strip()[:200]


def check_php(files, case_dir):
    for f in files:
        rc, out = run(['php', '-l', f])
        if rc != 0:
            return 'FAIL', first_line(out, re.compile('error', re.I))
    return 'OK', ''


def check_js(files, case_dir):
    # Not `node --check`: on Node 22+ it returns 0 for any file module detection reads as ESM,
    # syntax or no syntax. stubs/javascript/parse-check.js parses with V8 as a script, then as a
    # module, and reports JSX as unchecked.
    script = os.path.join(EVALS, 'stubs', 'javascript', 'parse-check.js')
    rc, out = run(['node', '--experimental-vm-modules', '--no-warnings', script] + files)
    lines = [l for l in out.splitlines() if l.startswith(('FAIL', 'UNCHECKED'))]
    fails = [l for l in lines if l.startswith('FAIL')]
    if fails or (rc != 0 and not lines):
        return 'FAIL', (fails[0].split(': ', 1)[-1] if fails else first_line(out))[:200]
    if lines:
        return 'UNCHECKED', lines[0].split(': ', 1)[-1][:200]
    return 'OK', ''


def check_py(files, case_dir):
    # py_compile writes bytecode into __pycache__ next to the source unless told otherwise, which
    # would leave 50-odd untracked directories inside the fixtures; compile into a temp file.
    with tempfile.TemporaryDirectory() as td:
        for f in files:
            rc, out = run([sys.executable, '-c',
                           'import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)',
                           f, os.path.join(td, 'out.pyc')])
            if rc != 0:
                return 'FAIL', first_line(out, re.compile('Error'))
    return 'OK', ''


def check_go(files, case_dir):
    for f in files:
        rc, out = run(['gofmt', '-e', '-l', f])
        if rc != 0:
            return 'FAIL', first_line(out)
    return 'OK', ''


def check_perl(files, case_dir):
    # perl -c stops at the first `use` it cannot load, so a missing module would leave the rest of
    # the file unchecked. Modules the fixtures use but do not ship are compile-only stand-ins under
    # stubs/perl/lib; case-local .pm files resolve from the case directory. There is no static
    # type checker for Perl, so this compile phase (with `use strict` catching undeclared
    # variables) is the ceiling.
    stub_lib = os.path.join(EVALS, 'stubs', 'perl', 'lib')
    for f in files:
        rc, out = run(['perl', '-I', stub_lib, '-I', case_dir, '-c', f], cwd=case_dir)
        if rc != 0:
            return 'FAIL', first_line(out, re.compile("syntax error|Unmatched|Missing|Bareword|Can't locate|Global symbol"))
    return 'OK', ''


def check_java(files, case_dir):
    with tempfile.TemporaryDirectory() as td:
        rc, out = run(['javac', '-proc:none', '-Xmaxerrs', '500', '-d', td] + files, cwd=case_dir)
    if rc == 0:
        return 'OK', ''
    errors = [l for l in out.splitlines() if ' error: ' in l]
    syntax = [l for l in errors if not JAVA_RESOLUTION.search(l)]
    if syntax:
        return 'FAIL', syntax[0].strip()[:200]
    return 'OK', f'{len(errors)} unresolved references (no classpath)'


def check_cs(files, case_dir):
    with tempfile.TemporaryDirectory() as td:
        proj = os.path.join(td, 'case.csproj')
        items = '\n'.join(f'    <Compile Include="{f}" />' for f in files)
        io.open(proj, 'w', encoding='utf-8').write(
            '<Project Sdk="Microsoft.NET.Sdk.Web">\n'
            '  <PropertyGroup><TargetFramework>net8.0</TargetFramework><Nullable>disable</Nullable>'
            '<ImplicitUsings>enable</ImplicitUsings><EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
            '<TreatWarningsAsErrors>false</TreatWarningsAsErrors><GenerateAssemblyInfo>false</GenerateAssemblyInfo></PropertyGroup>\n'
            f'  <ItemGroup>\n{items}\n  </ItemGroup>\n</Project>\n')
        rc, out = run(['dotnet', 'build', proj, '-nologo', '-v', 'q', '--no-restore', '-p:RestorePackagesPath=' + os.path.join(td, 'pk')], cwd=td, timeout=300)
        if rc != 0 and 'NETSDK1004' in out or 'project.assets.json' in out:
            rc, out = run(['dotnet', 'build', proj, '-nologo', '-v', 'q'], cwd=td, timeout=300)
    if rc == 0:
        return 'OK', ''
    errors = sorted({l.strip() for l in out.splitlines() if CS_ANY.search(l)})
    syntax = [l for l in errors if CS_ANY.search(l).group(1) in CS_SYNTAX_CODES]
    if syntax:
        return 'FAIL', re.sub(r'^.*?\(', '(', syntax[0])[:200]
    if errors:
        return 'OK', f'{len(errors)} unresolved references (no packages)'
    return 'FAIL', first_line(out, re.compile('error'))


_VSDEVCMD = None


def vsdevcmd():
    """Path to Visual Studio's developer command script, or '' if MSVC's C++ toolset is absent.
    On a machine without gcc/clang this is how cl.exe and the Windows SDK reach the PATH."""
    global _VSDEVCMD
    if _VSDEVCMD is None:
        _VSDEVCMD = ''
        vswhere = os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                               'Microsoft Visual Studio', 'Installer', 'vswhere.exe')
        if os.path.exists(vswhere):
            rc, out = run([vswhere, '-latest', '-products', '*', '-requires',
                           'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-find', r'Common7\Tools\VsDevCmd.bat'])
            if rc == 0 and out.strip():
                _VSDEVCMD = out.strip().splitlines()[0]
    return _VSDEVCMD


def msvc_syntax_check(files, cpp, cwd):
    """cl /Zs: parse plus full semantic analysis, no code generation. Returns (rc, output).
    Goes through a generated batch file: the developer script has to run in the same cmd as cl,
    and cmd's quoting of a one-line `call ... && cl ...` handed over by subprocess is unreliable."""
    compat = os.path.join(EVALS, 'stubs', 'c', 'msvc_compat.h')
    flags = (f'/nologo /Zs /W0 /EHsc /FI"{compat}" /I"{os.path.dirname(compat)}" '
             + ('/TP /std:c++20' if cpp else '/TC /std:c17'))
    quoted = ' '.join(f'"{os.path.abspath(f)}"' for f in files)
    with tempfile.NamedTemporaryFile('w', suffix='.bat', delete=False, encoding='ascii', newline='\r\n') as bat:
        bat.write('@echo off\n')
        bat.write(f'call "{vsdevcmd()}" -arch=x64 -no_logo >nul 2>&1\n')
        bat.write(f'cl {flags} {quoted}\n')
        bat.write('exit /b %ERRORLEVEL%\n')
    try:
        return run(['cmd', '/c', bat.name], cwd=cwd, timeout=300)
    finally:
        os.unlink(bat.name)


def check_c(files, case_dir, cpp=False):
    cc = shutil.which('clang++' if cpp else 'clang') or shutil.which('g++' if cpp else 'gcc')
    srcs = [f for f in files if not f.endswith(('.h', '.hpp'))] or files
    if cc:
        # Same language levels as the MSVC branch (/std:c17, /std:c++20): std::span fixtures
        # need C++20, and the compiler's default is gnu++17. gnu_compat.h declares gets() for C.
        std = ['-std=c++20'] if cpp else ['-include', os.path.join(EVALS, 'stubs', 'c', 'gnu_compat.h')]
        for f in srcs:
            rc, out = run([cc, '-fsyntax-only', '-w'] + std + [f], cwd=case_dir)
            if rc != 0:
                return 'FAIL', first_line(out, re.compile('error'))
        return 'OK', ''
    if vsdevcmd():
        rc, out = msvc_syntax_check(srcs, cpp, case_dir)
        if rc != 0:
            return 'FAIL', first_line(out, re.compile(r'error C\d{4}'))
        return 'OK', 'msvc /Zs'
    return 'UNCHECKED', 'no C/C++ compiler on PATH'


CHECKERS = {
    'php': ('php', check_php, ('.php',)),
    'javascript': ('node', check_js, ('.js',)),
    'python': (sys.executable, check_py, ('.py',)),
    'go': ('gofmt', check_go, ('.go',)),
    'perl': ('perl', check_perl, ('.pl', '.pm')),
    'java': ('javac', check_java, ('.java',)),
    'csharp': ('dotnet', check_cs, ('.cs',)),
    'c': (None, lambda fs, d: check_c(fs, d, cpp=False), ('.c', '.h')),
    'cpp': (None, lambda fs, d: check_c(fs, d, cpp=True), ('.cpp', '.cc', '.hpp', '.h')),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', help='one CWE id')
    ap.add_argument('--lang')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--paths', nargs='*', help='check only the cases these files or directories fall under')
    args = ap.parse_args()

    wanted = None
    if args.paths is not None:
        wanted = set()
        for p in args.paths:
            if os.path.isabs(p):
                ap_ = os.path.abspath(p)
            elif os.path.exists(os.path.join(EVALS, p)):
                ap_ = os.path.abspath(os.path.join(EVALS, p))
            else:
                ap_ = os.path.abspath(os.path.join(REPO, p))
            rel = os.path.relpath(ap_, CASES).replace(os.sep, '/')
            parts = rel.split('/')
            if rel.startswith('..') or len(parts) < 3:
                continue
            wanted.add('/'.join(parts[:3]))
        if not wanted:
            print('no case paths among the given paths; nothing to check')
            return 0

    counts = {}
    failures, unchecked = [], []
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
                tool, fn, exts = CHECKERS.get(lang, (None, None, ()))
                files = sorted(os.path.join(case_dir, f) for f in os.listdir(case_dir)
                               if os.path.splitext(f)[1].lower() in exts)
                others = sorted(f for f in os.listdir(case_dir)
                                if f != 'case.json' and os.path.splitext(f)[1].lower() not in exts)
                if fn is None:
                    status, detail = 'UNCHECKED', f'no checker for {lang}'
                elif tool and not shutil.which(tool) and not os.path.exists(tool):
                    status, detail = 'UNCHECKED', f'{tool} not on PATH'
                elif not files:
                    status, detail = 'UNCHECKED', 'no source files with a known extension'
                else:
                    status, detail = fn(files, case_dir)
                if others and status == 'OK':
                    detail = (detail + '; ' if detail else '') + 'unchecked: ' + ', '.join(others)
                counts.setdefault(lang, {}).setdefault(status, 0)
                counts[lang][status] += 1
                if status == 'FAIL':
                    failures.append((key, detail))
                elif status == 'UNCHECKED':
                    unchecked.append((key, detail))
                if args.verbose or status != 'OK':
                    print(f'{status:9s} {key}: {detail}')
    print('\nsummary:')
    for lang in sorted(counts):
        print(f'  {lang:11s} ' + ', '.join(f'{k} {v}' for k, v in sorted(counts[lang].items())))
    print(f'{len(failures)} failing, {len(unchecked)} unchecked')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
