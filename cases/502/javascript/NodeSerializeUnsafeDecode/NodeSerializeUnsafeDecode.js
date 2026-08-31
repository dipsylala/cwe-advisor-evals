const express = require('express');
const serialize = require('node-serialize');

const app = express();

function parseProfileCookie(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/profile=([^;]+)/);
  if (!match) {
    req.profile = {};
    return next();
  }

  const encoded = match[1];
  const decoded = decodeURIComponent(encoded);

  // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
  req.profile = serialize.unserialize(decoded);

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
