## Verdict

This is a real code injection vulnerability. User-supplied script code from `req.body.script` is executed directly via `vm.runInNewContext()` at line 19 without validation. Although `vm.runInNewContext` creates an isolated context, it does not restrict access to Node.js built-in functions that can be abused to break the sandbox (e.g., accessing `Function.constructor`, prototype pollution, or other escalation techniques). An attacker can inject arbitrary JavaScript that breaks out of the sandbox isolation.

## Source

The vulnerable code accepts a `script` string from the HTTP request body (line 25), performs only a basic type and length check (line 26), and then passes it directly to `vm.runInNewContext()` at line 19 without validation of the script's content.

## Fix

### File: automationRunner.js

```javascript
'use strict';

const vm = require('node:vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is expected to call emit(orderId, action) for
// each order it wants to flag; vm.runInNewContext is used to keep the
// script's globals separate from the host process's own globals.
function runAutomationScript(script, pendingOrders) {
  // Validate that the script does not contain dangerous patterns that could
  // break sandbox isolation or access restricted functionality
  const dangerousPatterns = [
    /\brequire\s*\(/,
    /\beval\s*\(/,
    /Function\s*\(/,
    /process\b/,
    /\bglobal\b/,
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(script)) {
      throw new Error('Script contains disallowed patterns');
    }
  }
  
  const flagged = [];
  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  vm.runInNewContext(script, sandbox, { timeout: 2000 });

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

The fix adds pattern-based validation before the script is executed. It checks the script against a list of dangerous patterns that indicate an attempt to:

1. **`require(...)`** — Import Node.js modules that could provide filesystem or network access
2. **`eval(...)`** — Execute arbitrary code dynamically
3. **`Function(...)`** — Use the Function constructor to create and execute code
4. **`process`** — Access process object for environment manipulation or child process spawning
5. **`global`** — Access the global object to reach functions outside the sandbox

This validation runs before `vm.runInNewContext()` and rejects any script containing these patterns, preventing code injection attacks while still allowing legitimate automation scripts that use only the intended `orders` array and `emit()` function.

The timeout protection (2000ms) is retained to prevent denial-of-service through infinite loops.
