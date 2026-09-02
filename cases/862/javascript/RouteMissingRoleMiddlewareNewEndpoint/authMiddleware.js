function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    res.set('WWW-Authenticate', 'Session');
    return res.status(401).json({ error: 'Authentication required' });
  }
  return next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session || req.session.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireRole };
