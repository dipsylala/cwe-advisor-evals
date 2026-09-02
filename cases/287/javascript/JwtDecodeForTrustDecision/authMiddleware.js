// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.decode() never checks a signature at any
// version of this package - it is a plain base64 decode of the payload.
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
  const payload = jwt.decode(token);

  if (!payload || !payload.userId) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (payload.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required' });
  }

  req.user = { id: payload.userId, role: payload.role };
  next();
}

module.exports = { requireAdmin };
