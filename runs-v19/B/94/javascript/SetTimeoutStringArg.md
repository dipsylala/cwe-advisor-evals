## Verdict

Code injection confirmed at line 28. User input flows from `req.body.message` (line 15) into a dynamically generated code string (line 25) that is passed to `setTimeout()` for evaluation (line 28). The `message` parameter is interpolated directly into the string without escaping, allowing an attacker to close the enclosing quotes and inject arbitrary JavaScript code.

## Source

User-controlled input from `req.body.message` is extracted at line 15 and concatenated into a code string at line 25 without proper escaping. The string is then passed to `setTimeout()` at line 28, where it is evaluated as JavaScript code.

Attack example: `message = '") + alert("pwned") + ("'` produces:
```
recordReminder("...", "") + alert("pwned") + ("")
```

## Fix

Replace the string-based `setTimeout()` call with a function callback that calls `recordReminder()` directly, eliminating dynamic code generation:

### File: SetTimeoutStringArg.js

```javascript
const express = require('express');
const router = express.Router();

// In-memory log of reminder events fired by scheduled timers.
const reminderLog = [];

function recordReminder(reminderId, message) {
  reminderLog.push({ reminderId, message, firedAt: new Date().toISOString() });
}

// POST /api/reminders
// Body: { reminderId: string, message: string, delayMs: number }
// Schedules a reminder that appends an entry to reminderLog once delayMs elapses.
router.post('/api/reminders', (req, res) => {
  const { reminderId, message, delayMs } = req.body;

  if (!reminderId || !message || !Number.isFinite(delayMs)) {
    return res.status(400).json({ error: 'reminderId, message, and delayMs are required' });
  }

  // Use a callback function instead of passing a code string to setTimeout.
  // This eliminates the injection point by avoiding dynamic code generation.
  setTimeout(() => {
    recordReminder(reminderId, message);
  }, delayMs);

  res.status(202).json({ status: 'scheduled', reminderId });
});

module.exports = { router, reminderLog, recordReminder };
```

## Explanation

The original code builds a JavaScript source string by concatenating user-supplied values and passes that string to `setTimeout()`, which evaluates it as code. An attacker can inject arbitrary code by breaking out of the string quotes.

The fix passes a function callback to `setTimeout()` instead of a string. The closure captures `reminderId` and `message` as variables, and `recordReminder()` is invoked directly without any string concatenation or code evaluation. This eliminates the dynamic code generation pattern entirely, removing the injection sink.

The fix preserves the original behavior: `recordReminder()` is still called after the specified delay with the provided parameters.

## Behaviour changes

None. The fixed code calls `recordReminder(reminderId, message)` after `delayMs` milliseconds, preserving the intended functionality.
