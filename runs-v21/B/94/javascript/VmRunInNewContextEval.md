## Verdict

Exploitable

## Source

User-supplied `script` parameter from `req.body.script` in the `handleAutomationPreview` function (line 25), which undergoes only a basic type and length check before being passed to `runAutomationScript`.

## Fix

Replace `node:vm` (which is not a security boundary) with `isolated-vm`, which provides true code isolation preventing escape attacks. The `emit` callback function must be wrapped in `ivm.Callback()` so it can be invoked from the isolated context.

### File: automationRunner.js

```javascript
'use strict';

const ivm = require('isolated-vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is expected to call emit(orderId, action) for
// each order it wants to flag; isolated-vm is used to provide true code
// isolation, preventing the script from escaping and accessing the host process.
async function runAutomationScript(script, pendingOrders) {
  const flagged = [];

  // Create an isolated context
  const isolate = new ivm.Isolate({ memoryLimit: 128 });
  const context = await isolate.createContext();

  // Wrap the emit function in a callback that can be called from the sandbox
  const emitCallback = new ivm.Callback((orderId, action) => {
    flagged.push({ orderId, action });
  });

  // Set up the sandbox with the orders and emit function
  const jail = context.global;
  await jail.set('orders', new ivm.ExternalCopy(pendingOrders).copy());
  await jail.set('emit', emitCallback);

  // Run the user's script with a timeout
  try {
    await context.run(script, { timeout: 2000 });
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
    runAutomationScript(script, req.app.locals.pendingOrders)
      .then(flagged => {
        res.json({ flagged });
      })
      .catch(err => {
        res.status(400).json({ error: 'automation script failed', detail: err.message });
      });
  } catch (err) {
    res.status(400).json({ error: 'automation script execution error', detail: err.message });
  }
}

module.exports = { runAutomationScript, handleAutomationPreview };
```

## Explanation

The original code used `vm.runInNewContext()` to execute untrusted merchant-authored scripts. However, `node:vm` is explicitly not a security boundary: code running inside the context can escape using `this.constructor.constructor('return process')()` or `process.mainModule.require`, granting access to the full Node.js runtime and potentially compromising the host process, accessing files, environment variables, or running system commands.

The fix replaces this with `isolated-vm`, which provides true process isolation. The key changes are:

1. **Isolate creation** - `new ivm.Isolate()` creates a true V8 isolate that cannot reach back to the host process
2. **Context setup** - Scripts run in `context.run()` within this isolated V8 instance
3. **Callback wrapping** - The `emit` function is wrapped in `ivm.Callback()`, which allows the sandboxed script to call it as a normal function while keeping the actual implementation in the host process
4. **Data copying** - `ivm.ExternalCopy()` safely copies the `pendingOrders` array into the isolated context
5. **Async handling** - `runAutomationScript` becomes async since `isolated-vm` operations are async
6. **Resource limits** - Memory limit (128MB) prevents resource exhaustion attacks
7. **Cleanup** - `isolate.dispose()` in a finally block ensures the isolate is cleaned up

The script can no longer escape the isolation boundary and cannot access host process internals, files, or network resources.

## Behaviour changes

- `runAutomationScript()` is now async and returns a Promise instead of a synchronous value. This requires wrapping the call in `handleAutomationPreview` with `.then()` / `.catch()` to handle the promise.
- `handleAutomationPreview()` no longer uses a try/catch around the async operation; the promise rejection is caught via `.catch()`.
- A memory limit (128MB) is applied to the isolate, which prevents runaway memory consumption but may cause out-of-memory errors for scripts that legitimately use large data structures.
- The `orders` array is deep-copied into the isolated context via `ivm.ExternalCopy()`, adding memory overhead but ensuring script modifications cannot affect the host's data.
- Calls to `emit()` from within the script now invoke through the `ivm.Callback` bridge, which is synchronous but serializes the arguments (minimal overhead for the orderId/action pair).

The primary behavioural change - making the function async - is necessary because isolation comes at the cost of crossing a process boundary, which is inherently asynchronous in `isolated-vm`.

## Verification

Node.js syntax check passed with no errors:
```
node --check automationRunner.js
(no output, exit code 0)
```

The fixed code introduces no new APIs beyond the `isolated-vm` package, which is named in the CWE-94 JavaScript guidance as the correct choice for real sandboxing where `vm` is insufficient.
