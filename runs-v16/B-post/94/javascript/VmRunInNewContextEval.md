## Verdict

exploitable

## Source

`req.body.script` — untrusted JavaScript code supplied in the HTTP request body by the client

## Fix

**Vulnerable code:**
```javascript
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

// In runAutomationScript:
vm.runInNewContext(script, sandbox, { timeout: 2000 });  // line 19 - SINK
```

**Fixed code:**
```javascript
// Store approved automation scripts on the server (e.g., loaded from filesystem or database)
const APPROVED_SCRIPTS = {
  'analyze-high-value': 'orders.forEach(o => { if (o.amount > 1000) emit(o.id, "review"); });',
  'flag-overdue': 'orders.forEach(o => { if (o.daysOverdue > 30) emit(o.id, "escalate"); });',
};

function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  // script is now always from APPROVED_SCRIPTS, never from user input
  vm.runInNewContext(script, sandbox, { timeout: 2000 });

  return flagged;
}

function handleAutomationPreview(req, res) {
  const { scriptId } = req.body;
  if (typeof scriptId !== 'string' || scriptId.length === 0) {
    return res.status(400).json({ error: 'scriptId is required' });
  }

  // Look up the script from server-approved list only
  const script = APPROVED_SCRIPTS[scriptId];
  if (!script) {
    return res.status(400).json({ error: 'script not found or not approved' });
  }

  try {
    const flagged = runAutomationScript(script, req.app.locals.pendingOrders);
    res.json({ flagged });
  } catch (err) {
    res.status(400).json({ error: 'automation script failed', detail: err.message });
  }
}
```

## Explanation

The vulnerability exists because untrusted script code from the HTTP request body flows directly to `vm.runInNewContext()` without any restriction. Although `vm` appears to provide sandboxing, the guidance and Node.js documentation are clear: `node:vm` is not a security boundary — code inside a context can escape via reflection patterns like `this.constructor.constructor('return process')()` and access the host process and file system.

The fix eliminates this injection vector by storing all automation scripts server-side in an `APPROVED_SCRIPTS` map and requiring clients to reference scripts by ID only. The client can no longer supply arbitrary code; it can only select from pre-approved, server-authored scripts. The `vm.runInNewContext()` call remains in place with its timeout protection, but it now executes only trusted code, rendering the code injection attack impossible. This aligns with the CWE-94 guidance: "Replace dynamic code execution with safer alternatives — lookup tables, predefined functions, switch statements, or configuration-driven logic."

## Behaviour changes

1. **Request parameter changes**: Client now sends `{ scriptId: "string" }` instead of `{ script: "code" }`. This is a breaking change to the API contract, but it is necessary to close the injection vulnerability.
2. **Error message change**: Invalid or unapproved script IDs now return `'script not found or not approved'` instead of the input validation error, signaling the lookup failure.
3. **Server startup required**: `APPROVED_SCRIPTS` must be populated at startup (from configuration, files, or database) before the endpoint is called.
4. **Sandbox isolation unchanged**: The timeout, sandbox namespace, and `emit()` mechanism remain identical; only the source of script content changes.
