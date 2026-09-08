## Verdict

Confirmed. `runAutomationScript` passes an attacker-controlled string straight into `vm.runInNewContext`, which compiles and executes it as JavaScript. Node's own documentation is explicit that the `vm` module "does not provide a security mechanism for running untrusted code" - sandboxed globals and a `timeout` option stop neither a synchronous CPU-bound loop that never yields nor access to the sandbox object graph itself, and a script that reaches back through `sandbox.orders` or its own prototype chain can still influence host-side state or throw to exfiltrate data via the caught error message. Any script content supplied by a merchant is arbitrary code execution in the host process, not "isolated" automation.

## Source

`handleAutomationPreview` reads `script` directly from `req.body` (an HTTP request body under full caller control) and passes it unmodified to `runAutomationScript(script, req.app.locals.pendingOrders)`, which forwards it to `vm.runInNewContext` at line 19. Nothing between the request body and the sink parses, validates, or constrains the string - it is treated as executable source the whole way.

## Fix

### File: automationRunner.js

```javascript
'use strict';

const ALLOWED_OPERATORS = new Set(['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'contains']);

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is a declarative list of rules (plain JSON data,
// never compiled or executed as code): each rule's `when` conditions are
// evaluated against every pending order, and a match flags the order with
// the rule's `action`. Because no script text is ever handed to a JS
// engine, a malicious merchant payload cannot run code in the host
// process - it can only fail validation.
function evaluateCondition(order, condition) {
  if (!condition || typeof condition !== 'object') {
    throw new Error(`invalid condition: ${JSON.stringify(condition)}`);
  }
  const { field, operator, value } = condition;
  if (typeof field !== 'string' || !ALLOWED_OPERATORS.has(operator)) {
    throw new Error(`invalid condition: ${JSON.stringify(condition)}`);
  }

  const actual = order[field];
  switch (operator) {
    case 'eq':
      return actual === value;
    case 'ne':
      return actual !== value;
    case 'gt':
      return actual > value;
    case 'gte':
      return actual >= value;
    case 'lt':
      return actual < value;
    case 'lte':
      return actual <= value;
    case 'contains':
      return typeof actual === 'string' && typeof value === 'string' && actual.includes(value);
    default:
      return false;
  }
}

function runAutomationScript(rules, pendingOrders) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new Error('rules must be a non-empty array');
  }

  const flagged = [];
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || typeof rule.action !== 'string' || rule.action.length === 0) {
      throw new Error(`invalid rule: ${JSON.stringify(rule)}`);
    }
    const conditions = Array.isArray(rule.when) ? rule.when : [rule.when];

    for (const order of pendingOrders) {
      const matches = conditions.every((condition) => evaluateCondition(order, condition));
      if (matches) {
        flagged.push({ orderId: order.id, action: rule.action });
      }
    }
  }

  return flagged;
}

function handleAutomationPreview(req, res) {
  const { rules } = req.body;
  if (!Array.isArray(rules) || rules.length === 0) {
    return res.status(400).json({ error: 'rules is required' });
  }

  try {
    const flagged = runAutomationScript(rules, req.app.locals.pendingOrders);
    res.json({ flagged });
  } catch (err) {
    res.status(400).json({ error: 'automation script failed', detail: err.message });
  }
}

module.exports = { runAutomationScript, handleAutomationPreview };
```

## Explanation

The `vm` module cannot be hardened into a safe boundary for this use case - no combination of context options, `timeout`, or global stripping turns it into a security sandbox, per Node's own documentation, so patching the call (e.g. tightening the sandbox object or lowering the timeout) leaves the same class of finding in place. The only fix that actually removes code injection is to stop compiling merchant input as source at all.

The replacement keeps the same observable contract the rest of the application depends on - `runAutomationScript(input, pendingOrders)` returns the same `[{ orderId, action }, ...]` shape, and `handleAutomationPreview` still validates the request body and responds with the same success/error JSON envelope - but the input is now a JSON-serializable list of declarative rules (`{ when: [{ field, operator, value }], action }`) instead of a string of JavaScript. `evaluateCondition` reads a named field off each order and compares it with a fixed, explicit operator set; there is no code path that interprets `field`, `operator`, or `value` as anything other than inert data, so there is no way to smuggle executable behavior through them. A merchant who previously wrote a script now expresses the same "flag orders matching X" intent as data, and the automation feature keeps working with the actual vulnerable primitive removed rather than defended.
