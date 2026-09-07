## Verdict

Exploitable. The `message` parameter from `req.body.message` flows directly into a string passed to `setTimeout()` without proper escaping or sanitization. A message containing a double quote and arbitrary JavaScript code breaks out of the string literal and executes with application privileges.

## Source

HTTP request body field `message` (line 15: `const { reminderId, message, delayMs } = req.body;`) flows through string concatenation into the setTimeout sink without escaping.

## Fix

**Vulnerable code (lines 24-28):**
```javascript
const deferredStatement =
  'recordReminder(' + JSON.stringify(reminderId) + ', "' + message + '")';

// SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
setTimeout(deferredStatement, delayMs);
```

**Fixed code:**
```javascript
setTimeout(() => {
  recordReminder(reminderId, message);
}, delayMs);
```

## Explanation

The fix eliminates code generation entirely. Instead of building a string that `setTimeout()` evaluates as JavaScript, the replacement passes a callback function (an arrow function) to `setTimeout()`. The parameters `reminderId` and `message` are captured in the closure as data values, not embedded in source text. This removes the injection point: untrusted input no longer influences what code executes. The `recordReminder` call happens identically, but it is now invoked by the JavaScript engine directly rather than through string evaluation. `setTimeout()` remains responsible for scheduling the callback after `delayMs` milliseconds, preserving the original timing behavior.

## Behaviour changes

None. The fixed code preserves all aspects of the original sink contract: `setTimeout()` is called with a callback and a delay, the callback executes after the delay elapses, and `recordReminder()` is called with the same parameters and at the same point in the execution flow. The change is internal to how the callback is provided—as a function literal instead of a string—and eliminates the vulnerability without altering the application's observable behavior.
