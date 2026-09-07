## Verdict

Exploitable. User-supplied script from `req.body.script` flows directly to `vm.runInNewContext()`, which is not a security boundary. Attackers can escape the sandbox using prototype chain traversal (`this.constructor.constructor('return process')()`) or access `process.mainModule.require()`, gaining arbitrary code execution with full process capabilities.

## Source

User input: `script` parameter from `req.body` in the HTTP request handler `handleAutomationPreview()` (line 25). The parameter passes a basic type check (`typeof script !== 'string'`) but no validation that would prevent malicious code.

Sink: `vm.runInNewContext(script, sandbox, { timeout: 2000 })` at line 19.

Data flow: `req.body.script` → `handleAutomationPreview()` → `runAutomationScript(script, ...)` → `vm.runInNewContext(script, sandbox, ...)`.

## Fix

Replace the `node:vm` module with the `isolated-vm` package, which provides true process isolation that attackers cannot escape. The `isolated-vm` package creates a completely isolated V8 context that prevents access to the host process's internals.

### File: automationRunner.js

```javascript
'use strict';

const IsolatedVm = require('isolated-vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is expected to call emit(orderId, action) for
// each order it wants to flag; isolated-vm provides a truly isolated V8
// context that prevents escaping the sandbox.
function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const isolate = new IsolatedVm.Isolate({ memoryLimit: 128 });
  const context = isolate.createContextSync();
  
  // Copy orders data into the isolated context
  context.global.setSync('orders', new IsolatedVm.ExternalCopy(pendingOrders).copyInto());
  
  // Create a reference to the emit function that the script can call back to
  const emitRef = new IsolatedVm.Reference((orderId, action) => {
    flagged.push({ orderId, action });
  });
  context.global.setSync('emit', emitRef);

  // Run the script with a timeout in the isolated context
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

The original code uses `node:vm`'s `runInNewContext()`, which the Node.js documentation explicitly warns is not a security boundary. Attackers can escape using prototype chain traversal (`this.constructor.constructor('return process')()`) or access the host process through `process.mainModule.require()`. The timeout parameter prevents denial-of-service through infinite loops but does nothing to prevent code injection.

The fixed code replaces this with the `isolated-vm` npm package, which creates a completely isolated V8 isolate that has no access to the host process's internals. The script runs in this isolated context with:

- **Memory isolation**: The `memoryLimit: 128` restricts the isolate to 128 MB, preventing memory exhaustion attacks
- **No host access**: The script cannot reach `process`, `require()`, or the Node.js runtime
- **Timeout enforcement**: The 2000ms timeout still applies, but now runs within the isolated context
- **Callback support**: The `emit()` function still works through `IsolatedVm.Reference()`, which safely marshals calls back to the host with only the data that is explicitly passed (orderId and action)
- **Data isolation**: Orders are copied into the context using `ExternalCopy`, preventing the script from modifying the original array

## Behaviour changes

- **Dependency added**: Requires `isolated-vm` npm package (a native module that compiles against system V8)
- **Memory limit**: The isolate is capped at 128 MB to prevent resource exhaustion
- **Error propagation**: Errors from the isolated script still propagate as exceptions and are caught by the handler's try-catch, maintaining the same error response contract
- **Return value**: Still returns the `flagged` array as before; the interface is unchanged
- **Data format**: Orders and callback results use the same shape; no change to the data structures passed to/from the script
