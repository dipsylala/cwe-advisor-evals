## Verdict
exploitable

## Source
`message` field from `req.body` (line 15), untrusted user input supplied in the POST request body

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

  // Use a callback function instead of dynamic code evaluation.
  // reminderId and message are passed as function arguments, not evaluated as code.
  setTimeout(() => recordReminder(reminderId, message), delayMs);

  res.status(202).json({ status: 'scheduled', reminderId });
});

module.exports = { router, reminderLog, recordReminder };
```

## Explanation
The vulnerability occurs when the `message` field is concatenated directly into a string evaluated by `setTimeout()`. An attacker can break out of the string context by supplying a message like `x", 'injected code'); //` to inject arbitrary JavaScript code. The fix replaces the string-based code construction with an arrow function callback, passing `reminderId` and `message` as function arguments rather than embedding them in evaluated code. This prevents code injection because the values are passed to the function at call time rather than being parsed and executed as source text.

## Behaviour changes
none
