const express = require('express');
const app = express();

app.use(express.json());

const pendingInvites = new Map();

// Generate a single-use invite code for the email address supplied by the
// caller and email it to them so they can join the workspace.
app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
  const inviteCode = Math.random().toString(36).slice(2, 10);

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
