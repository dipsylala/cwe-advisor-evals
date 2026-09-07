#!/usr/bin/env python3
"""Classify compile-gate failures by kind, so a results file can say what a FAIL was.

The gate (fixgate.py) records the compiler's first error. This turns that line into one of:

    missing-import      a real class the fix did not import (Java and C#: the simple name exists
                        in the JDK / .NET reference assemblies or on the superset classpath)
    unresolved-name     a class, type, function or variable nothing defines (invented, wrong
                        package, or a library the superset lacks - see missing-package)
    unresolved-member   a method, field or export the named type or module does not have
    signature           a real API called with the wrong arguments or types
    syntax              does not parse
    unused              Go's unused import or variable
    missing-package     a package or module that is not installed
    runtime             the checker rejects something that fails at run time (an invalid regex)
    other               none of the patterns matched

Usage:
    python evals/scripts/gatekinds.py <gate.json> [--write]

Prints the per-arm kind table; --write adds `kind` (and `kind_detail`) to every record in place.
fixgate.py calls classify() at gate time, so a fresh gate.json already carries the field.

The Java and C# symbol indexes are built once per machine from the JDK image (`jimage list`),
the superset classpath jars, the .NET reference-assembly XML docs and the restored NuGet
packages' XML docs, and cached under stubs/<language>/.symbol-index.json (ignored by git).
"""
import argparse
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict

EVALS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUBS = os.path.join(EVALS, 'stubs')

RULES = {
    'java': [
        (r'package [\w.]+ does not exist', 'missing-package'),
        (r'cannot find symbol \(symbol:\s+method', 'unresolved-member'),
        (r'cannot find symbol \(symbol:\s+(class|variable)', 'unresolved-name'),
        (r'cannot find symbol', 'unresolved-name'),
        (r'incompatible types|cannot be applied|no suitable|cannot be converted', 'signature'),
        (r'expected|illegal start|unclosed|not a statement|reached end of file', 'syntax'),
    ],
    'csharp': [
        (r'CS0246|CS0234|CS0103', 'unresolved-name'),
        (r'CS1061|CS0117|CS0122', 'unresolved-member'),
        (r'CS1503|CS1501|CS7036|CS0029|CS0266|CS1729|CS1502|CS0121|CS0019', 'signature'),
        (r'CS1002|CS1003|CS1010|CS1513|CS1026|CS1525|CS1519|CS8803', 'syntax'),
    ],
    'go': [
        (r'imported and not used|declared and not used', 'unused'),
        (r'missing go\.sum|cannot find module|no required module', 'missing-package'),
        (r'undefined: ', 'unresolved-name'),
        (r'has no field or method|undefined \(type', 'unresolved-member'),
        (r'cannot use|not enough arguments|too many arguments|mismatched types|does not implement', 'signature'),
        (r'syntax error|expected', 'syntax'),
    ],
    'python': [
        (r'import-not-found', 'missing-package'),
        (r'name-defined', 'unresolved-name'),
        (r'attr-defined|no attribute', 'unresolved-member'),
        (r'call-arg|arg-type|call-overload|too many arguments|missing positional', 'signature'),
        (r'\[syntax\]|SyntaxError|invalid syntax', 'syntax'),
    ],
    'php': [
        (r'(Function|Class|Constant|Interface) .* not found|Instantiated class .* not found', 'unresolved-name'),
        (r'undefined (method|static method|property|constant)', 'unresolved-member'),
        (r'Syntax error|phpstan\.parse', 'syntax'),
        (r'Regex pattern is invalid', 'runtime'),
        (r'expects|Parameter #|invoked with', 'signature'),
    ],
    'javascript': [
        (r"package '[^']*' not found", 'missing-package'),
        (r'has no export', 'unresolved-member'),
        (r'SyntaxError', 'syntax'),
        (r'does not resolve|Cannot find module', 'unresolved-name'),
    ],
    'c': [
        (r'C2065|undeclared identifier|use of undeclared|implicit declaration|not declared', 'unresolved-name'),
        (r'C2039|no member named|is not a member|has no member', 'unresolved-member'),
        (r'C2664|C2660|C2661|no matching function|too (few|many) arguments|incompatible (pointer|integer)', 'signature'),
        (r'C2338|static assertion|cannot convert|invalid conversion', 'signature'),
        (r'C2018|C2143|C2059|C2146|expected', 'syntax'),
    ],
    'perl': [
        (r'is not exported', 'unresolved-member'),
        (r"Can't locate", 'missing-package'),
        (r'Global symbol', 'unresolved-name'),
        (r'syntax error', 'syntax'),
    ],
}
RULES['cpp'] = RULES['c']

JAVA_NAME = re.compile(r'symbol:\s+class (\w+)')
CS_NAME = re.compile(r"CS0246: The type or namespace name '(\w+)'|CS0103: The name '(\w+)'")


# ---------------------------------------------------------------- symbol indexes
def _cache(lang):
    return os.path.join(STUBS, lang, '.symbol-index.json')


def _load(lang):
    p = _cache(lang)
    if os.path.exists(p):
        return json.load(io.open(p, encoding='utf-8'))
    return None


def _save(lang, index):
    io.open(_cache(lang), 'w', encoding='utf-8').write(json.dumps(index))


def java_index():
    """simple class name -> sorted list of packages, from the JDK image and the superset classpath."""
    idx = _load('java')
    if idx is not None:
        return idx
    names = defaultdict(set)
    javac = shutil.which('javac')
    if javac:
        home = os.path.dirname(os.path.dirname(os.path.realpath(javac)))
        jimage = os.path.join(home, 'bin', 'jimage.exe' if os.name == 'nt' else 'jimage')
        modules = os.path.join(home, 'lib', 'modules')
        if os.path.exists(jimage) and os.path.exists(modules):
            out = subprocess.run([jimage, 'list', modules], capture_output=True, text=True, errors='replace').stdout
            for line in out.splitlines():
                line = line.strip()
                if line.endswith('.class') and '$' not in line:
                    pkg, _, cls = line[:-6].rpartition('/')
                    names[cls].add(pkg.replace('/', '.'))
    cp = os.path.join(STUBS, 'java', 'classpath.txt')
    if os.path.exists(cp):
        for jar in io.open(cp, encoding='utf-8').read().strip().split(os.pathsep):
            if not jar.endswith('.jar') or not os.path.exists(jar):
                continue
            try:
                with zipfile.ZipFile(jar) as z:
                    for n in z.namelist():
                        if n.endswith('.class') and '$' not in n and '/' in n:
                            pkg, _, cls = n[:-6].rpartition('/')
                            names[cls].add(pkg.replace('/', '.'))
            except zipfile.BadZipFile:
                continue
    idx = {k: sorted(v) for k, v in names.items()}
    if idx:
        _save('java', idx)
    return idx


def csharp_index():
    """simple type name -> sorted list of namespaces, from the .NET reference packs' XML docs and the
    XML docs of every restored NuGet package."""
    idx = _load('csharp')
    if idx is not None:
        return idx
    names = defaultdict(set)
    files = []
    dotnet = shutil.which('dotnet')
    if dotnet:
        root = os.path.dirname(os.path.realpath(dotnet))
        # Whatever reference pack is installed (net8.0 here, net10.0 on a newer SDK): the BCL's
        # type names are stable enough for a "does this simple name exist" lookup.
        for pack in ('Microsoft.NETCore.App.Ref', 'Microsoft.AspNetCore.App.Ref'):
            files += glob.glob(os.path.join(root, 'packs', pack, '*', 'ref', '*', '*.xml'))
    nuget = os.path.join(os.path.expanduser('~'), '.nuget', 'packages')
    assets = os.path.join(STUBS, 'csharp', 'obj', 'project.assets.json')
    if os.path.exists(assets):
        libs = json.load(io.open(assets, encoding='utf-8')).get('libraries', {})
        for lib in libs:
            name, _, ver = lib.partition('/')
            files += glob.glob(os.path.join(nuget, name.lower(), ver, 'lib', '*', '*.xml'))
    pat = re.compile(r'name="T:([\w.]+?)(?:`\d+)?"')
    for f in files:
        try:
            text = io.open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for full in pat.findall(text):
            ns, _, cls = full.rpartition('.')
            names[cls].add(ns)
    idx = {k: sorted(v) for k, v in names.items()}
    if idx:
        _save('csharp', idx)
    return idx


# ---------------------------------------------------------------- classification
def classify(lang, status, note):
    """Return (kind, detail) for one gate record."""
    if status != 'FAIL':
        return '', ''
    kind = 'other'
    for pat, k in RULES.get(lang, []):
        if re.search(pat, note):
            kind = k
            break
    detail = ''
    if kind == 'unresolved-name':
        name = None
        if lang == 'java':
            m = JAVA_NAME.search(note)
            name = m.group(1) if m else None
            idx = java_index() if name else {}
        elif lang == 'csharp':
            m = CS_NAME.search(note)
            name = (m.group(1) or m.group(2)) if m else None
            idx = csharp_index() if name else {}
        else:
            idx = {}
        if name and name in idx:
            kind = 'missing-import'
            detail = f'{name} exists in {", ".join(idx[name][:3])}'
        elif name:
            detail = f'{name} exists nowhere in the index'
    return kind, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('gate_json')
    ap.add_argument('--write', action='store_true')
    args = ap.parse_args()
    gate = json.load(io.open(args.gate_json, encoding='utf-8'))
    table = defaultdict(Counter)
    for key, rec in gate.items():
        kind, detail = classify(rec['language'], rec['status'], rec.get('note', ''))
        rec['kind'], rec['kind_detail'] = kind, detail
        if kind:
            table[rec['arm']][kind] += 1
    kinds = sorted({k for c in table.values() for k in c})
    print(f"{'arm':<5}" + ''.join(f'{k:>18}' for k in kinds) + f"{'total':>8}")
    for arm in sorted(table):
        print(f'{arm:<5}' + ''.join(f'{table[arm][k]:>18}' for k in kinds) + f'{sum(table[arm].values()):>8}')
    print()
    for key in sorted(gate, key=lambda k: (gate[k]['kind'], k)):
        rec = gate[key]
        if rec['kind']:
            print(f"{rec['kind']:<18} {key}  {rec['kind_detail'] or rec['note'][:100]}")
    if args.write:
        io.open(args.gate_json, 'w', encoding='utf-8', newline='\n').write(json.dumps(gate, indent=1, sort_keys=True) + '\n')
        print('\nkinds written ->', args.gate_json)


if __name__ == '__main__':
    main()
