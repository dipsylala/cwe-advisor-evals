'use strict';

function allowSameOriginOrMissing(req) {
  const origin = req.get('origin') || req.get('referer');
  const expected = `${req.protocol}://${req.get('host')}`;

  if (origin && !origin.startsWith(expected)) {
    return false;
  }

  return true;
}

module.exports = { allowSameOriginOrMissing };
