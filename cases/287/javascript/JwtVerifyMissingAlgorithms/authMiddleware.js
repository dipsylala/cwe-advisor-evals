// authMiddleware.js
// Express middleware that authenticates API requests using an RS256-signed
// JWT. The RSA public key is loaded once at startup and used to verify the
// bearer token on every request. Targets jsonwebtoken 9.0.2.

const fs = require('fs');
const jwt = require('jsonwebtoken');

const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, 'utf8');

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
    const claims = jwt.verify(token, publicKey);
    req.user = { id: claims.sub, roles: claims.roles || [] };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth };
