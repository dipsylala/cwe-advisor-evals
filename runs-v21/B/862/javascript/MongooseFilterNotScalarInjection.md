## Verdict

exploitable

## Source

`req.body.extra` - attacker-controlled data from the JSON request body that is directly spread into the Mongoose query filter without validation or allowlisting.

## Fix

### File: orderRoutes.js

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const Order = require('./orderModel');

const router = express.Router();

// POST /orders/:id/details - fetch a single order belonging to the
// authenticated caller. The mobile client may pass extra match criteria in
// the request body (for example { extra: { status: 'shipped' } }) so a
// lookup can be narrowed without a second round trip.
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  // Only allow specific safe scalar fields from extraCriteria to prevent
  // authorization bypass via Mongoose operators or property override.
  const allowedFields = ['status', 'type', 'priority'];
  const safeExtraCriteria = {};
  
  for (const field of allowedFields) {
    if (field in extraCriteria) {
      // Coerce to string to prevent nested objects with $ operators
      const value = extraCriteria[field];
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        safeExtraCriteria[field] = value;
      }
    }
  }

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...safeExtraCriteria,
  };

  try {
    const order = await Order.findOne(filter);

    if (!order) {
      res.status(404).json({ error: 'not_found' });
      return;
    }

    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'lookup_failed' });
  }
});

module.exports = router;
```

## Explanation

The original code spreads untrusted data from `req.body.extra` directly into the Mongoose query filter, allowing an attacker to override the `ownerId` authorization check. An attacker could inject `{ "extra": { "ownerId": null } }` or `{ "extra": { "ownerId": { "$ne": "legitimate_owner_id" } } }` to retrieve orders belonging to other users. The fix validates the extra criteria by maintaining an allowlist of safe fields (`status`, `type`, `priority`) and only including scalar values in the filter. Type checking prevents nested objects that could contain Mongoose operators. The `ownerId` ownership check remains mandatory and cannot be overridden, ensuring the authorization remains effective.

## Behaviour changes

The endpoint now only accepts specific whitelisted fields from `req.body.extra` instead of accepting any field. Non-scalar values (objects, arrays, null) are silently rejected from extra criteria, preventing both Mongoose operator injection and authorization bypass. This is a restriction that closes the vulnerability; legitimate clients passing `status`, `type`, or `priority` in `extra` will continue to work as intended.

