## Verdict

VULNERABLE. Untrusted input from `req.body.script` is passed directly to `vm.runInNewContext()` at line 19. Although the code uses a limited sandbox and timeout, Node's `vm` module is explicitly not a security boundary and can be escaped via constructor access or process.mainModule.require.

## Source

Line 25-26 in `handleAutomationPreview()`: the `script` parameter is received from `req.body.script` with only a type and length check. This untrusted input flows directly to `runAutomationScript()` at line 31, which passes it to `vm.runInNewContext(script, sandbox, ...)` at line 19.

## Fix

Replace `node:vm` with the `isolated-vm` package, which provides true out-of-process isolation:

```javascript
'use strict';

const {ivm} = require('isolated-vm');

function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  
  const isolate = new ivm.Isolate({ memoryLimit: 128 });
  const context = isolate.createContextSync();
  const jail = context.global;
  
  jail.setSync('orders', new ivm.ExternalCopy(pendingOrders).copyInto());
  jail.setSync('emit', new ivm.Reference(function(orderId, action) {
    flagged.push({ orderId, action });
  }));
  
  try {
    context.evalSync(script, { timeout: 2000 });
  } finally {
    isolate.dispose();
  }

  return flagged;
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

## Explanation

Node's `vm` module is not a security boundary; escape techniques like `this.constructor.constructor('return process')()` and `process.mainModule.require` allow code inside a context to access the host process. The `isolated-vm` package replaces `vm` with true process isolation: untrusted code runs in a separate V8 isolate with no access to Node's internals, file system, or network.

The fix preserves the original functionality—merchants can still supply automation scripts and call `emit()` to flag orders—while eliminating the escape vectors. The sandbox provides:
- **Isolation**: Code runs in a separate isolate, not just a namespace
- **Resource limits**: `memoryLimit: 128` (MB) prevents denial-of-service
- **Controlled APIs**: Only `orders` and `emit` are exposed; no constructors, process, or module loading
- **Timeout**: The `{ timeout: 2000 }` is now enforced by the isolate, not just by a host timer

Dependency: Add `isolated-vm` to `package.json` (current stable version).

## Behaviour changes

The merchant-supplied script sees identical `orders` and `emit()` APIs and produces the same `flagged` output. The HTTP endpoint behavior is unchanged: successful scripts return flagged orders; exceptions are caught and returned as error responses. The key difference is that any attempt to escape the sandbox (via constructor, prototype chain, or module access) now fails silently inside the isolate instead of succeeding in the host process.
