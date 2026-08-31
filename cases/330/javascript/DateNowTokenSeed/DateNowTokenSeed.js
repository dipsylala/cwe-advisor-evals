const express = require('express');
const router = express.Router();

const resetTokens = new Map();

// Generate a password reset token for the account tied to the submitted email.
router.post('/forgot-password', (req, res) => {
  const email = req.body.email;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email is required' });
  }

  // SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
  const token = Math.random().toString(36).substring(2);

  resetTokens.set(token, { email, expires: Date.now() + 3600000 });

  sendResetEmail(email, token);

  res.json({ message: 'If that email exists, a reset link was sent.' });
});

function sendResetEmail(email, token) {
  console.log(`Reset link for ${email}: https://example.com/reset?token=${token}`);
}

module.exports = router;
