## Verdict

Exploitable.

## Source

`reminderId` and `message` from `req.body` in the POST request handler (lines 15).

## Fix

**Vulnerable code (line 28):**
```javascript
const deferredStatement =
  'recordReminder(' + JSON.stringify(reminderId) + ', "' + message + '")';

setTimeout(deferredStatement, delayMs);
```

**Fixed code:**
```javascript
setTimeout(() => {
  recordReminder(reminderId, message);
}, delayMs);
```

## Explanation

The vulnerability occurs because `message` is concatenated directly into a string that `setTimeout()` will evaluate as JavaScript code. An attacker can inject code by supplying a `message` containing a double-quote character (e.g., `"); malicious code; //`) that breaks out of the string literal and injects arbitrary JavaScript. The fix replaces the string with a function callback, which safely closes over the variables without requiring dynamic code evaluation. The callback captures `reminderId` and `message` from the request scope and passes them to `recordReminder()` when the timer fires, eliminating the code injection sink entirely.

## Behaviour changes

None. The fixed code preserves the original contract: it schedules `recordReminder()` to be called after `delayMs` milliseconds with the same arguments that were being passed before. The only difference is that the code is no longer constructed from strings at runtime - it is static and safe. The arrow function callback uses lexical scoping to capture the variables in scope, requiring no changes to how `recordReminder()` is called or what arguments it receives.
