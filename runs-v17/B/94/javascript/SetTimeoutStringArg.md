## Verdict

exploitable

## Source

HTTP POST body parameter `message` (line 15) passed from `req.body` without validation, concatenated directly into dynamically evaluated code string.

## Fix

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

  // FIXED: Pass a callback function instead of building and evaluating a code string.
  // This eliminates code injection because no user input flows into evaluated text.
  setTimeout(() => {
    recordReminder(reminderId, message);
  }, delayMs);

  res.status(202).json({ status: 'scheduled', reminderId });
});

module.exports = { router, reminderLog, recordReminder };
```

## Explanation

The original code constructed a string containing function call syntax by concatenating user-supplied `reminderId` and `message` values, then passed that string to `setTimeout()`, which evaluates it as code. Although `reminderId` was JSON-stringified, `message` was wrapped in literal quotes without escaping, allowing an attacker to inject code. For example, a message value `foo", alert("pwned')` would break out of the string context and execute arbitrary code. The fix replaces the dynamic string evaluation with a callback function that captures `reminderId` and `message` as closure variables and invokes `recordReminder()` directly. No code generation occurs, so there is no injection surface.

## Behaviour changes

The `setTimeout()` call now receives a function callback instead of a string, which is the safe form of the API. The semantics remain identical: the callback executes after `delayMs` milliseconds and calls `recordReminder()` with the same arguments. No return value, output, or side effect changes. The function has access to `reminderId` and `message` through lexical scope rather than string evaluation, so parameter passing is preserved without requiring code text generation.
