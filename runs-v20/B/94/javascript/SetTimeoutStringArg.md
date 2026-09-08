## Verdict

exploitable

- **cwe_id**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **location**: `SetTimeoutStringArg.js`, line 28 (sink); construction at line 24-25
- **confidence**: high

## Source

`reminderId` and `message` come from `req.body` in the `POST /api/reminders` Express handler (line 15) - both are attacker-controlled HTTP request fields. Only a truthiness check is applied (line 17); neither value is escaped, length-capped, or restricted to a safe character set before use.

## Fix

Sink contract established before changing it: `setTimeout(code, delayMs)` schedules `code` to run after `delayMs` and returns a `Timeout` object; the handler never captures that return value, so nothing downstream depends on it. There is no third-argument callback-arg usage, and the string form of `setTimeout` has no distinct failure behavior from the function form - both silently swallow a throw from inside the callback (an uncaught exception on the timer surfaces as an `uncaughtException` either way). So a plain function callback preserves every part of the contract the code relies on.

The source, `reminderId` and `message`, is spliced into a JavaScript source-text string (`deferredStatement`) which `setTimeout` compiles and executes as code when the timer fires (line 28). Per the JavaScript CWE-94 guidance, this is the canonical `setTimeout(string)` taint sink: any request body containing `"` followed by a call expression (e.g. `message = '"); require("child_process").execSync("id"); //'`) breaks out of the intended `recordReminder(...)` call and runs arbitrary code with full access to the process (filesystem, env vars, network).

The remediation guidance's first Remediation Step for this file's exact pattern is direct: "Convert `setTimeout(string)` to `setTimeout(function)` with callbacks." Applying it removes the string-building step entirely - `reminderId` and `message` are passed as ordinary closed-over variables to `recordReminder`, never re-parsed as source text, so there is no code-generation step left for an attacker to influence.

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

  // Schedule the reminder with a function callback instead of building a source
  // string. reminderId and message are attacker-controlled request fields, but
  // they are now passed as ordinary arguments to recordReminder rather than
  // spliced into text that setTimeout would evaluate.
  setTimeout(() => {
    recordReminder(reminderId, message);
  }, delayMs);

  res.status(202).json({ status: 'scheduled', reminderId });
});

module.exports = { router, reminderLog, recordReminder };
```

## Explanation

The vulnerable code built a JavaScript source string via concatenation (`'recordReminder(' + JSON.stringify(reminderId) + ', "' + message + '")'`) and handed it to `setTimeout`, which compiles and executes string arguments as code - `JSON.stringify` only escaped `reminderId`'s slot, leaving `message` concatenated into the string with no escaping at all, so any `"` in `message` closes the string literal early and lets the attacker append arbitrary statements. The fix replaces the string with an arrow-function callback that closes over `reminderId` and `message` and calls `recordReminder` directly. This eliminates the code-generation step altogether: the values are runtime arguments to an ordinary function call, never re-interpreted as source text, so no input can escape into a new statement regardless of its content. No library recommendation applies - the guidance's fix here is a language-native pattern change, not a dependency.

**Verification**: `node --check` was run against the fixed file (copied to a scratch path outside the repository, not the case fixture) and completed with no syntax errors. By hand: `recordReminder` is called with the same two arguments and same order as the original construction (`reminderId`, `message`), matching its existing definition (line 7); no new imports, packages, or APIs were introduced - `setTimeout` with a function first argument is the same global already in use, just with its other supported argument type.

## Behaviour changes

- The `deferredStatement` variable and its comment are removed - they existed only to build the now-unnecessary source string; nothing else reads that variable.
- `recordReminder` is still invoked with the same two values, in the same order, after the same `delayMs` delay; `reminderLog` receives an identical entry shape (`{ reminderId, message, firedAt }`) to what the evaluated string would have produced for non-malicious input.
- The response (`202` with `{ status: 'scheduled', reminderId }`) is unchanged.
- No change to validation, status codes, or the `Timeout` object's (unused) return value.
- Net effect: none, for any legitimate input. The only behavior that changes is that a `message` or `reminderId` containing `"`, `)`, `;`, or other syntax-significant characters can no longer alter what code runs - they are stored and logged as literal data instead.
