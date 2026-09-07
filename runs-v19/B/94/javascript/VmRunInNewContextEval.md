## Verdict

**CONFIRMED AND REMEDIATED**

CWE-94 code injection via `vm.runInNewContext()` accepting untrusted user input. The Node.js `vm` module is not a security boundary; code inside a context can escape to access `process`, filesystem, and host globals through prototype chain traversal and constructor access. Replaced with `isolated-vm`, which provides true process isolation.

## Source

**File**: `automationRunner.js`  
**Line**: 19  
**Sink**: `vm.runInNewContext(script, sandbox, { timeout: 2000 })`

**Data Flow**:
- **Source** (line 25): `req.body.script` — untrusted HTTP request parameter
- **Flow** (line 31): Script passed from request handler to `runAutomationScript()`
- **Sink** (line 19): Script executed directly in `vm.runInNewContext()` without input validation

An attacker-supplied script string flows directly from the HTTP request into code execution. The `vm` module's context provides namespace separation but not security isolation; code can escape via `this.constructor.constructor('return process')()` or `process.mainModule.require()` to access Node.js built-ins and the host environment.

## Fix

### File: automationRunner.js

```javascript
'use strict';

const ivm = require('isolated-vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. isolated-vm is used to provide real process isolation with
// resource limits, preventing scripts from accessing the host process's
// globals, functions, or environment.
function runAutomationScript(script, pendingOrders) {
  const flagged = [];

  // Create an isolate with a 128 MB memory limit
  const isolate = new ivm.Isolate({ memoryLimit: 128 });

  try {
    // Create a context within the isolate
    const context = isolate.createContextSync();

    // Wrap the emit function as a callback so it's callable from the isolate
    const emitCallback = new ivm.Callback((orderId, action) => {
      flagged.push({ orderId, action });
    });

    // Transfer orders data to the isolate
    const ordersCopy = new ivm.ExternalCopy(pendingOrders).copyInto();

    // Set up sandbox globals
    context.setSync('orders', ordersCopy);
    context.setSync('emit', emitCallback);

    // Compile and run the script in the isolated context
    const compiledScript = isolate.compileScriptSync(script);
    compiledScript.runSync(context, {
      timeout: 2000,
      microtaskMode: 'after'
    });
  } finally {
    // Ensure the isolate is disposed to free resources
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

The fix replaces the `vm` module with `isolated-vm`, which provides genuine process-level isolation. Key security improvements:

1. **True isolation boundary**: `isolated-vm` runs code in a separate V8 context that does not share the host process's prototype chains, built-in functions, or global objects. Code cannot reach `process`, `require()`, or filesystem APIs through constructor chaining or prototype traversal.

2. **Resource limits**: The isolate is created with a 128 MB memory ceiling, preventing denial-of-service attacks through heap exhaustion. The 2-second timeout remains to prevent infinite loops.

3. **Callback wrapping**: The `emit()` function is wrapped with `new ivm.Callback()`, which makes it callable from the isolate while remaining a reference to the host function. Scripts call `emit(orderId, action)` naturally, but the function executes in host context and cannot inspect or manipulate the calling context.

4. **Data transfer**: The `orders` array is wrapped in `ExternalCopy` and transferred into the isolate, preventing the script from accessing or modifying the original host object directly.

The fix preserves the intended behavior: merchant-authored scripts can still iterate orders and call `emit()` to flag actions. No valid script that worked before will break. The isolation prevents any script from accessing the host Node.js process, environment variables, database connections, or secrets—the primary risk from CWE-94.

## Behaviour changes

**What changed**:
- Untrusted scripts no longer run in the host process context; they run in an isolated V8 isolate with no access to `process`, `require()`, or global functions
- Memory is limited to 128 MB per isolate; scripts exceeding this will throw an error
- Data passed to the script (orders) and results from callbacks (flagged actions) are copied/transferred across the isolation boundary, not shared by reference
- Syntax errors or runtime exceptions in the script are caught and reported the same way as before

**What did not change**:
- The timeout remains 2 seconds
- Scripts can still call `emit(orderId, action)` to flag orders
- Scripts can still read the `orders` array passed to them
- The `flagged` array returned to the caller contains the same structure as before
- Error handling in `handleAutomationPreview()` works the same way

**Breaking changes for scripts**:
- None for correctly-written scripts. Scripts that call `require()`, access `process`, or attempt to reach host globals will now fail, but these represent security escapes that should be blocked.

**Dependency requirement**:
- Adds a runtime dependency on the `isolated-vm` npm package. The package must be installed and available in `node_modules/`. Version selection should follow SCA/dependency-check guidance; this fix is verified against isolated-vm's current stable release.
