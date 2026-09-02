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

  // Build the statement that will run when the timer fires. Both reminderId and
  // message are attacker-controlled request fields, spliced directly into the
  // source text that setTimeout will evaluate.
  const deferredStatement =
    'recordReminder(' + JSON.stringify(reminderId) + ', "' + message + '")';

  // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
  setTimeout(deferredStatement, delayMs);

  res.status(202).json({ status: 'scheduled', reminderId });
});

module.exports = { router, reminderLog, recordReminder };
