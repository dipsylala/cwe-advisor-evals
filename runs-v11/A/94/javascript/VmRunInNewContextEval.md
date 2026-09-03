## Verdict

Real vulnerability. User-supplied code is executed via `vm.runInNewContext()` with insufficient sandbox isolation, allowing sandbox escapes through prototype pollution and object manipulation.

## Source

Line 19 executes merchant-supplied `script` within a mutable sandbox object. The sandbox at lines 11–16 contains live references to the `orders` array and an `emit` function, both of which can be manipulated at runtime by the executed code. An attacker can modify `Object.prototype`, escape the sandbox, and access the host process.

## Fix

Freeze the sandbox object and all properties passed into it to prevent prototype pollution and property manipulation:

```javascript
function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const sandbox = {
    orders: Object.freeze([...pendingOrders]),
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  // Freeze the sandbox and all its properties to prevent escapes
  Object.freeze(sandbox);
  Object.freeze(Object.getPrototypeOf(sandbox));

  vm.runInNewContext(script, sandbox, { timeout: 2000 });

  return flagged;
}
```

Additionally, validate script syntax before execution:

```javascript
try {
  new vm.Script(script); // Validate syntax without executing
} catch (err) {
  throw new Error('Invalid script syntax: ' + err.message);
}
```

Insert this validation in `runAutomationScript()` before the `vm.runInNewContext()` call.

## Explanation

The timeout option alone does not prevent sandbox escapes. Attackers can modify `Object.prototype.constructor` or other prototype chains to gain access to the host's global object and execute arbitrary code outside the sandbox context. Freezing the sandbox object and its prototype prevents this class of attack.

Validating script syntax with `new vm.Script()` before execution catches syntax errors early without execution side effects, and provides defense-in-depth by ensuring only structurally valid code reaches the sandbox.

The code creates a defensive copy of `pendingOrders` with spread syntax and freezes it to prevent the sandbox code from modifying the input array, which could corrupt the host's state.
