## Verdict

CONFIRMED. The authorization check is incomplete. Line 19 spreads untrusted user input (`req.body.extra`) into the filter object without validation, allowing an attacker to inject MongoDB query operators or override the `ownerId` field and bypass ownership authorization.

## Source

The vulnerability occurs in the route handler that fetches a single order. The code retrieves `extraCriteria` from the request body (lines 14-15) and spreads it into the database filter without validation (line 19). An attacker can inject malicious query operators or override the authorization field `ownerId`, bypassing the ownership check.

Example attack: `{ extra: { ownerId: { $ne: req.user.id } } }` would match any order not owned by the attacker, exposing other users' orders.

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
  // Allowlist of safe filter fields that clients may provide.
  const ALLOWED_FILTER_FIELDS = new Set(['status', 'total', 'currency']);
  
  const extraCriteria = req.body.extra || {};
  
  // Build filter from allowlisted fields only.
  const safeExtra = {};
  for (const key of ALLOWED_FILTER_FIELDS) {
    if (key in extraCriteria) {
      safeExtra[key] = extraCriteria[key];
    }
  }

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...safeExtra,
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

The fix introduces an allowlist (`ALLOWED_FILTER_FIELDS`) of safe, non-authorization-critical fields that clients are permitted to filter by. The code builds `safeExtra` by copying only allowlisted keys from the user-supplied `extraCriteria`. This prevents an attacker from injecting MongoDB query operators or overriding the `_id` and `ownerId` fields that enforce authorization.

The authorization fields (`_id` and `ownerId`) are added to the filter after the allowlisted criteria, ensuring they cannot be overridden. The lookup now enforces both ownership and record ID authorization while safely accepting application-defined filtering criteria from the client.
