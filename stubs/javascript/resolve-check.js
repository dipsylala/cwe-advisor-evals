#!/usr/bin/env node
// Resolution check for JavaScript fixtures (driven by scripts/compilecheck.py).
//
// JavaScript has no compiler, so "does it resolve" is answered by loading: every bare specifier
// in require()/import must resolve from the superset node_modules next to this file, every
// relative specifier must resolve from the case directory, and every name destructured from a
// require() - `const { parse } = require('expr-eval')` - must be an export of the loaded module.
// That last check is the one that catches the run-16 slip shape (a named export that does not
// exist). A module whose native binding cannot load here is reported as unchecked, not failed.
//
// Usage: node resolve-check.js <file.js>...   (prints one line per problem; exit 1 if any FAIL)
'use strict';
const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');

const supersetRequire = createRequire(path.join(__dirname, 'package.json'));
const files = process.argv.slice(2);
let failures = 0;

const RE_REQ = /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)(?:\.([A-Za-z_$][\w$]*))?/g;
const RE_BARE_REQ = /require\(\s*(['"])([^'"]+)\1\s*\)/g;
const RE_IMPORT = /import\s+(?:(\{[^}]*\})|(\*\s+as\s+[\w$]+)|([\w$]+)(?:\s*,\s*\{([^}]*)\})?)\s+from\s+(['"])([^'"]+)\5/g;

function bareName(spec) {
  if (spec.startsWith('node:')) return null;
  if (spec.startsWith('.') || spec.startsWith('/')) return null;
  return spec;
}

function loadBare(spec) {
  try {
    return { mod: supersetRequire(spec) };
  } catch (e) {
    const msg = String(e && e.message || e);
    if (e && e.code === 'MODULE_NOT_FOUND' && msg.includes(`'${spec}'`)) return { missing: true };
    return { unloadable: msg.split('\n')[0].slice(0, 120) };
  }
}

// A relative specifier resolves in the case directory, or in the case's stub mirror under
// evals/stubs/javascript/cases/<cwe>/<lang>/<id>/ for collaborators the fixture does not ship.
function stubDirFor(caseDir) {
  const parts = path.resolve(caseDir).split(path.sep);
  const i = parts.lastIndexOf('cases');
  if (i < 0 || parts.length < i + 4) return null;
  return path.join(__dirname, 'cases', parts[i + 1], parts[i + 2], parts[i + 3]);
}

function exists(base) {
  return [base, base + '.js', base + '.json', path.join(base, 'index.js')]
    .some(p => fs.existsSync(p) && fs.statSync(p).isFile());
}

function checkRelative(caseDir, spec) {
  if (exists(path.resolve(caseDir, spec))) return true;
  const stubs = stubDirFor(caseDir);
  if (!stubs) return false;
  // The fixture file may sit one level below its app root ('../models/User'); the stub mirror is
  // flat, so a leading '../' is also tried against the mirror root itself.
  return exists(path.resolve(stubs, spec)) || exists(path.resolve(stubs, spec.replace(/^\.\.\//, './')));
}

function namesOf(destructure) {
  return destructure.replace(/[{}]/g, '').split(',').map(s => s.trim()).filter(Boolean)
    .map(s => s.split(':')[0].trim()).filter(n => /^[A-Za-z_$][\w$]*$/.test(n));
}

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const caseDir = path.dirname(file);
  const rel = path.relative(process.cwd(), file);
  const seen = new Set();
  const report = (kind, msg) => { console.log(`${kind} ${rel}: ${msg}`); if (kind === 'FAIL') failures++; };

  // 1. every specifier resolves
  for (const m of src.matchAll(RE_BARE_REQ)) {
    const spec = m[2];
    if (seen.has('r:' + spec)) continue;
    seen.add('r:' + spec);
    const bare = bareName(spec);
    if (bare === null) {
      if (!spec.startsWith('node:') && !checkRelative(caseDir, spec)) report('FAIL', `relative require '${spec}' does not resolve in the case directory`);
      continue;
    }
    const r = loadBare(bare);
    if (r.missing) report('FAIL', `package '${bare}' not found in the superset`);
    else if (r.unloadable) report('UNCHECKED', `'${bare}' present but cannot load here: ${r.unloadable}`);
  }
  for (const m of src.matchAll(RE_IMPORT)) {
    const spec = m[6];
    if (seen.has('r:' + spec)) continue;
    seen.add('r:' + spec);
    const bare = bareName(spec);
    if (bare === null) {
      if (!spec.startsWith('node:') && !checkRelative(caseDir, spec)) report('FAIL', `relative import '${spec}' does not resolve in the case directory`);
      continue;
    }
    const r = loadBare(bare);
    if (r.missing) report('FAIL', `package '${bare}' not found in the superset`);
    else if (r.unloadable) report('UNCHECKED', `'${bare}' present but cannot load here: ${r.unloadable}`);
    else if (m[1] || m[4]) {
      for (const n of namesOf(m[1] || m[4])) if (!(n in r.mod)) report('FAIL', `'${bare}' has no export '${n}'`);
    }
  }
  // 2. destructured / member requires name real exports
  for (const m of src.matchAll(RE_REQ)) {
    const spec = m[3];
    const bare = bareName(spec);
    if (bare === null) continue;
    const r = loadBare(bare);
    if (!r.mod) continue;
    const wanted = m[1].startsWith('{') ? namesOf(m[1]) : (m[4] ? [m[4]] : []);
    for (const n of wanted) if (!(n in r.mod)) report('FAIL', `'${bare}' has no export '${n}'`);
  }
}
process.exit(failures ? 1 : 0);
