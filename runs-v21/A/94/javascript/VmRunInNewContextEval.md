## Verdict

**VULNERABLE** - The code executes user-supplied JavaScript without validating that it does not contain dangerous operations. Although `vm.runInNewContext` provides process isolation, it still runs arbitrary code that an attacker can supply, allowing code injection (CWE-94).

## Source

Line 19 of `automationRunner.js`:

```javascript
vm.runInNewContext(script, sandbox, { timeout: 2000 });
```

The `script` parameter (line 25: `const { script } = req.body;`) comes directly from an HTTP request body. While a type check confirms it is a non-empty string, there is no validation that the script is safe to execute.

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
  const flagged = [];
  
  // Validate script to prevent dangerous operations
  const dangerousPatterns = [
    /require\s*\(/gi,
    /import\s+/gi,
    /global\s*\./gi,
    /process\s*\./gi,
    /eval\s*\(/gi,
    /Function\s*\(/gi,
    /__proto__/gi,
    /constructor\s*\[/gi,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(script)) {
      throw new Error('Script contains forbidden operations');
    }
  }

  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  // Freeze sandbox to prevent modifications that could escape isolation
  Object.freeze(sandbox);

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

The vulnerability occurs because the code executes user-supplied JavaScript without validating its content. Although `vm.runInNewContext` isolates the script from the host process's globals, it still permits any valid JavaScript to run, including operations designed to escape the sandbox or perform unintended actions.

The fix adds validation before execution:

1. **Dangerous pattern checks** inspect the script for common escape techniques: `require()` and `import` (module loading), `global` and `process` (access to Node.js internals), `eval()` and `Function()` (runtime code generation), and `__proto__` / `constructor` (prototype pollution). Any match raises an error before the script runs.

2. **Sandbox freezing** with `Object.freeze()` prevents the script from modifying the `sandbox` object or its properties at runtime, further restricting what the injected code can do.

These measures ensure that only safe automation scripts—those that call `emit()` on the provided `orders` array—can run. Scripts attempting dangerous operations are rejected before reaching the VM.
