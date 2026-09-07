## Verdict
CONFIRMED - CWE-862 Missing Authorization

## Source
The vulnerability exists because `extraCriteria` from the request body is merged directly into the filter without sanitization. An attacker can supply operator objects (e.g., `{ ownerId: { $ne: null } }`) that override the authorization check on `ownerId`, allowing access to orders belonging to other users.

## Fix

### File: orderRoutes.js
```javascript
'use strict';

const express = require('express');
const mongoose = require('mongoose');
const { requireAuth } = require('./sessionAuth');
const Order = require('./orderModel');

const router = express.Router();

// POST /orders/:id/details - fetch a single order belonging to the
// authenticated caller. The mobile client may pass extra match criteria in
// the request body (for example { extra: { status: 'shipped' } }) so a
// lookup can be narrowed without a second round trip.
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  // Sanitize extraCriteria to remove any MongoDB operators and ensure
  // only scalar values are used, preventing authorization bypass
  const sanitizedExtra = mongoose.sanitizeFilter(extraCriteria);

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...sanitizedExtra,
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
The fix applies `mongoose.sanitizeFilter()` to `extraCriteria` before merging it into the filter. This function removes any MongoDB query operators from the user-supplied object, ensuring that only scalar values are passed to the query. This prevents an attacker from injecting operators like `{ $ne: null }` or `{ $regex: '.' }` that could override the authorization check on `ownerId`. The authorization check (combining `_id` and `ownerId` from the authenticated user) remains intact and cannot be bypassed.
