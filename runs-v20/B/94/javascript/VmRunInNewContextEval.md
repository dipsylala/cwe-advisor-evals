## Verdict

exploitable

- **cwe_id**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **location**: `automationRunner.js`, line 19 (sink), function `runAutomationScript`
- **confidence**: high

## Source

`req.body.script` in `handleAutomationPreview` (line 25) — an HTTP request body field, fully attacker-controlled. It is validated only for type and non-empty length (lines 26-28), then passed unmodified as the `script` parameter of `runAutomationScript` (line 31), which forwards it unmodified into the sink at line 19. No sanitization, allowlisting, or AST validation occurs anywhere on this path.

## Fix

### File: automationRunner.js

```javascript
'use strict';

const ivm = require('isolated-vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is expected to call emit(orderId, action) for
// each order it wants to flag; isolated-vm runs the script in a separate
// V8 isolate (a real process/memory boundary, unlike node:vm) so the
// script cannot reach back into the host process.
function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const isolate = new ivm.Isolate({ memoryLimit: 8 });
  try {
    const context = isolate.createContextSync();
    context.global.setSync('orders', pendingOrders, { copy: true });
    context.global.setSync('emit', new ivm.Callback((orderId, action) => {
      flagged.push({ orderId, action });
    }));

    const compiled = isolate.compileScriptSync(script);
    compiled.runSync(context, { timeout: 2000 });

    return flagged;
  } finally {
    isolate.dispose();
  }
}

function handleAutomationPreview(req, res) {
  const { script } = req.body;
  if (typeof script !== 'string' || script.length === 0) {
    return res.status(400).json({ error: 'script is required' });
  }

  try {
    const flagged = runAutomationScript(script, req.app.locals.pendingOrders);
    res.json({ flagged });
  } catch (err) {
    res.status(400).json({ error: 'automation script failed', detail: err.message });
  }
}

module.exports = { runAutomationScript, handleAutomationPreview };
```

**library_recommendation**: `isolated-vm`. The loaded guidance does not carry a minimum safe version for this package; confirm the resolved version against SCA/dependency-check tooling before merging. Add it to `package.json` dependencies (`npm install isolated-vm`) — no other manifest change is prescribed here since none was supplied in the original fixture.

## Explanation

`vm.runInNewContext` sends the entire request-body string straight into V8 as executable source with only a wall-clock timeout; per this repository's `cwe/94/javascript` guidance, `node:vm` is not a security boundary because sandboxed code can reach the host process through the constructor chain (`this.constructor.constructor('return process')()`) or `process.mainModule.require`, regardless of how sparse the sandbox object is. The feature genuinely requires executing merchant-supplied logic (it is not translatable to a static lookup table), so per the guidance's isolation-as-control step the fix swaps `node:vm` for `isolated-vm`, which runs the script in a separate V8 isolate with its own heap — a real process/memory boundary rather than a shared-heap object wrapper. The `orders` data is copied into the isolate with `{ copy: true }` (isolate boundaries do not share live object references), and the `emit` callback is exposed via `new ivm.Callback(fn)` so the script's existing `emit(orderId, action)` call sites keep working unchanged. A `memoryLimit: 8` (MB) is set on the isolate as the guidance's recommended defense-in-depth memory cap, alongside the pre-existing 2000ms timeout, and the isolate is disposed in a `finally` block since isolates (unlike `vm` contexts) hold native resources that are not garbage-collected implicitly.

## Behaviour changes

- **New dependency**: `isolated-vm` replaces the built-in `node:vm` module — required to move from a shared-heap sandbox to a real isolate boundary; not swappable for a config/lookup-table rewrite because the feature's whole purpose is executing merchant-defined logic.
- **Added memory cap (`memoryLimit: 8` MB)**: the original had no memory limit at all, only the timeout. This is an additive resource constraint recommended by the guidance as defense-in-depth against DoS; a legitimate script that needs more than 8MB of isolate heap would newly fail. 8MB is generous for the described use case (iterating an order list and calling `emit`), but this is a judgment call, not a value taken from the original code.
- **Isolate/context disposal (`isolate.dispose()` in `finally`)**: not present before because `vm` contexts require no manual cleanup; `isolated-vm` isolates hold native memory and must be disposed explicitly to avoid a resource leak across repeated calls. This is required for correct use of the new sink, not a functional change visible to callers.
- **Error message text on a bad script**: a syntax error now originates from `isolate.compileScriptSync` (isolated-vm's V8 binding) instead of `vm.runInNewContext`. `err.message` is still caught by `handleAutomationPreview`'s existing `try/catch` and returned in the same `{ error, detail }` shape at the same 400 status, but the exact wording of `detail` may differ from before.
- Everything else is unchanged: `runAutomationScript` keeps the same synchronous signature and return value (the `flagged` array, populated via `emit` the same way), the 2000ms timeout is preserved, and `handleAutomationPreview`'s request validation, response shape, and status codes are untouched.

## Verification

Ran `node --check` against the fixed file in a scratch copy outside the repository (not the fixture in `evals/cases/`); it reported no syntax errors. `isolated-vm` was not installed in this environment, so module resolution/runtime behavior of the new dependency was not exercised — this is recorded as an assumption below rather than a verified fact.

**assumptions**:
- `ivm.Isolate`, `isolate.createContextSync`, `context.global.setSync`, `ivm.Callback`, `isolate.compileScriptSync`, `script.runSync`, and `isolate.dispose` are taken directly from this repository's `cwe/94/javascript/INDEX.md` guidance, which documents the `ivm.Callback` requirement specifically to avoid the "emit is not a function" failure mode; these were not independently re-verified against the installed package or npm registry in this environment, since `isolated-vm` is not present locally and no network/package check was performed.
- `memoryLimit: 8` (MB) was chosen as a reasonable default for this workload since neither the original code nor the loaded guidance specifies a value; a legitimate script with unusually large data needs could require raising it.
- No minimum safe version of `isolated-vm` is asserted, per the loaded guidance carrying none — confirm via SCA tooling before merging.
