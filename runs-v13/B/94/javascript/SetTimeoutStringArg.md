## Verdict

Exploitable. Attacker-controlled `message` from `req.body` flows into a dynamically constructed code string passed to `setTimeout()` with a string argument, which evaluates the string as JavaScript code.

## Source

Request body fields `reminderId` and `message` from the POST endpoint `/api/reminders` (lines 15, attacker-controlled).

## Fix

**Vulnerable code (line 24-28):**
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

The original code constructs a JavaScript string by concatenating the attacker-controlled `message` field directly into source text, then passes that string to `setTimeout()`. When `setTimeout()` receives a string argument, it evaluates it as code in the application's runtime context. An attacker can inject arbitrary JavaScript by closing the string and adding new statements—for example, a `message` value of `foo"); require('child_process').execSync('whoami'); ("` produces executable code that breaks out of the intended `recordReminder()` call. The fix replaces the string-based approach with a callback function that calls `recordReminder()` with the values as JavaScript arguments, eliminating code generation entirely. The `reminderId` and `message` are now passed as data, not as code text, and no evaluation occurs.

## Behaviour changes

None. The callback function executes the same `recordReminder()` call with the same arguments as the original dynamically generated string. `setTimeout()` still receives a function reference and a delay in milliseconds, and the timer fires after the specified delay, recording the reminder in the log as before.
