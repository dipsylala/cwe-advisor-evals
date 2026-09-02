'use strict';

function requireAuth(req, res, next) {
  if (!req.user) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  next();
}

module.exports = { requireAuth };
