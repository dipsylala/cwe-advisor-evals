const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// Encrypts a note's body using a passphrase supplied by the client.
router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  // SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
  const cipher = crypto.createCipher('aes-256-cbc', passphrase);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({ ciphertext: encrypted });
});

module.exports = router;
