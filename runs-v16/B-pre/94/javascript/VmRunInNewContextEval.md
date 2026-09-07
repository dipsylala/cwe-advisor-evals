## Verdict
Exploitable. Untrusted user input (`req.body.script`) flows directly to `vm.runInNewContext()` at line 19 with no content validation. The `node:vm` module is documented as not a security boundary; code inside the context can escape via `this.constructor.constructor()` or `process.mainModule.require`.

## Source
`req.body.script` (line 25 in `handleAutomationPreview`) — untrusted HTTP request body, passed as the `script` parameter to `runAutomationScript()` with only a type check (`typeof script !== 'string'`), no content validation.

## Fix

**Vulnerable code:**
```javascript
const vm = require('node:vm');

function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  // VULNERABLE: vm.runInNewContext is not a security boundary
  vm.runInNewContext(script, sandbox, { timeout: 2000 });

  return flagged;
}
```

**Fixed code:**
```javascript
const IsolatedVm = require('isolated-vm');

function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const isolate = new IsolatedVm.Isolate({ memoryLimit: 128 });
  const context = isolate.createContextSync();

  // Expose only the minimal APIs needed: orders and emit.
  // All other global access is blocked by isolation.
  context.global.setSync('orders', new IsolatedVm.ExternalCopy(pendingOrders).copy());
  context.global.setSync('emit', new IsolatedVm.ExternalCopy((orderId, action) => {
    flagged.push({ orderId, action });
  }).copy());

  try {
    // Run the script in true V8 context isolation with timeout enforcement.
    // This prevents escape attacks like this.constructor.constructor() that bypass vm module.
    context.evalSync(script, { timeout: 2000 });
  } finally {
    // Always dispose the isolate to prevent resource leaks.
    isolate.dispose();
  }

  return flagged;
}
```

**Library recommendation:**
Replace `node:vm` with the `isolated-vm` package. The version must be obtained from SCA/dependency-check tooling; the guidance does not specify a minimum safe version. Add to package.json as a production dependency.

## Explanation
The `node:vm` module is not a security boundary — code inside a context can escape via introspection paths like `this.constructor.constructor('return process')()` or `process.mainModule.require` to access the host process. The fix replaces `vm.runInNewContext()` with `isolated-vm`, which provides true V8 context isolation at the process level, preventing these escape techniques. The script still runs with a 2000ms timeout and the same limited API surface (`orders` and `emit`), but the isolation is now enforced by V8's memory boundaries, not by namespace filtering. The `memoryLimit: 128` (128 MB) cap prevents memory exhaustion attacks. The isolate is disposed in a `finally` block to ensure cleanup even if the script throws or times out.

## Behaviour changes
- **Added resource limit**: `memoryLimit: 128` (128 MB per isolate). The original code had no memory cap; malicious scripts could attempt denial of service via memory exhaustion. The new limit enforces a reasonable ceiling for a script sandbox.
- **Changed return value handling**: The original `vm.runInNewContext()` returned the last expression value, which was discarded. The fixed `context.evalSync()` also returns this value but it is similarly discarded, so the contract is preserved.
- **Added explicit cleanup**: `isolate.dispose()` is called in `finally` to free V8 resources. The original code relied on garbage collection. The new pattern is more deterministic and prevents resource leaks in long-running processes.
- **Dependency addition**: Requires adding `isolated-vm` as a production dependency.
