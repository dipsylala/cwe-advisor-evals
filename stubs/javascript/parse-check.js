#!/usr/bin/env node
// Parse check for JavaScript fixtures (driven by scripts/parsecheck.py and fixgate.py).
//
// `node --check` is not enough: on Node 22+ a file that module detection classifies as ESM (it
// contains `import` or `export`) returns 0 from --check whatever its syntax, so a broken ESM
// fixture passed. A file passes here if V8 parses it as a CommonJS script or as an ES module.
// A React component written in JSX is not JavaScript syntax; it is reported unchecked rather
// than failed, the same way framework-hosted templates are.
//
// Usage: node --experimental-vm-modules parse-check.js <file.js>...
//        (prints one line per problem; exit 1 if any FAIL)
'use strict';
const fs = require('fs');
const vm = require('vm');

let failures = 0;
for (const file of process.argv.slice(2)) {
  const src = fs.readFileSync(file, 'utf8');
  let err = null;
  try { new vm.Script(src, { filename: file }); continue; } catch (e) { err = e; }
  try { new vm.SourceTextModule(src, { identifier: file }); continue; } catch (e) { err = e; }
  if (/from\s+['"]react['"]|require\(\s*['"]react['"]\s*\)/.test(src) && /Unexpected token '<'/.test(err.message)) {
    console.log(`UNCHECKED ${file}: JSX is not JavaScript syntax`);
    continue;
  }
  console.log(`FAIL ${file}: SyntaxError: ${err.message}`);
  failures++;
}
process.exit(failures ? 1 : 0);
