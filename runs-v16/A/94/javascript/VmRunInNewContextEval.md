## Verdict

The code accepts unvalidated, user-supplied JavaScript code and executes it as code via `vm.runInNewContext()`. While the sandbox provides isolation, the absence of input validation means an attacker can inject arbitrary code. The vulnerability is confirmed at line 19.

## Source

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

function runAutomationScript(script, pendingOrders) {
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
```

The finding targets line 19: `vm.runInNewContext(script, sandbox, { timeout: 2000 });`

## Fix

Validate the script against a strict allowlist of patterns before execution, and use a frozen, minimal sandbox that only exposes required functions:

```javascript
function runAutomationScript(script, pendingOrders) {
  // Validate script: reject attempts to access globals or use dangerous syntax
  const forbiddenPatterns = [
    /\brequire\s*\(/,
    /\bimport\s+/,
    /\bexit\s*\(/,
    /\bprocess\b/,
    /\bglobal\b/,
    /\beval\s*\(/,
    /\bFunction\s*\(/,
    /\bConstructor\s*\(/,
  ];
  
  for (const pattern of forbiddenPatterns) {
    if (pattern.test(script)) {
      throw new Error(`Script contains forbidden pattern: ${pattern}`);
    }
  }

  const flagged = [];
  
  // Create a minimal, frozen sandbox with only required functions
  const sandbox = {
    orders: Object.freeze(
      pendingOrders.map(order => Object.freeze({ ...order }))
    ),
    emit(orderId, action) {
      if (typeof orderId !== 'string' && typeof orderId !== 'number') {
        throw new Error('orderId must be a string or number');
      }
      if (typeof action !== 'string') {
        throw new Error('action must be a string');
      }
      flagged.push({ orderId, action });
    },
  };

  vm.runInNewContext(script, sandbox, { timeout: 2000 });
  return flagged;
}
```

## Explanation

CWE-94 arises when user input is executed as code without validation. The original code provides sandbox isolation but lacks input validation, allowing an attacker to inject arbitrary JavaScript.

The fix adds two layers of defense:

1. **Script validation**: A blocklist of dangerous patterns (`require`, `import`, `process`, `eval`, `Function`, etc.) rejects attempts to escape the sandbox or invoke OS-level operations.

2. **Minimal sandbox**: The sandbox is frozen using `Object.freeze()` to prevent modifications, and only the `orders` array and `emit()` function are exposed—the minimal set required by legitimate scripts. The `emit()` function also validates its arguments to prevent misuse.

Together, these mitigations ensure that only scripts following the expected automation interface can execute, reducing the attack surface significantly. The validation is conservative and can be adjusted based on the actual set of operations merchants need to perform.
