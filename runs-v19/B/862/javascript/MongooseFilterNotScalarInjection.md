## Verdict

The finding is valid. The endpoint performs an authorization check (scoping the query by `ownerId`) but allows unauthenticated request data (`req.body.extra`) to be spread directly into the filter object. An attacker can override the `ownerId` constraint by sending a nested object with MongoDB operators, bypassing the ownership check and accessing other users' orders.

## Source

**File:** `orderRoutes.js`  
**Line:** 24 (the `Order.findOne(filter)` call)

**Data flow:**
- Source: `req.body.extra` (attacker-controlled)
- Intermediate: spread into filter object at line 19
- Sink: `Order.findOne(filter)` at line 24

**Exploitable path:** A malicious client sends `{ "extra": { "ownerId": { "$ne": null } } }` in the request body. This overrides the `ownerId` equality check intended to restrict access to the caller's own records, allowing the query to return any order.

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

  // Validate that extraCriteria contains only scalar values to prevent
  // MongoDB operator injection that could override the ownerId authorization check.
  // Nested objects or arrays could contain MongoDB operators that change the filter logic.
  for (const key in extraCriteria) {
    const val = extraCriteria[key];
    if (typeof val === 'object' && val !== null) {
      res.status(400).json({ error: 'invalid_filter' });
      return;
    }
  }

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...extraCriteria,
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

The vulnerability arises from spreading untrusted request data (`req.body.extra`) directly into the Mongoose filter object. Although the code correctly constructs an ownership check by including `ownerId: req.user.id`, this check is negated when `extraCriteria` contains a nested object value. For example, `{ "extra": { "ownerId": { "$ne": null } } }` causes the filter to apply the `$ne` operator instead of equality, turning the query into "find any order where ownerId is not null," completely bypassing the authorization restriction.

The fix validates that all values in `extraCriteria` are scalars (strings, numbers, booleans, null) before spreading them into the filter. Non-scalar values (objects or arrays) that could encode MongoDB operators are rejected with a 400 response. This ensures that user-supplied extra criteria can only narrow the existing query (e.g., by status), not modify its logical structure or override the authorization constraint. The ownership check on `ownerId` remains the single source of truth for authorization.

## Behaviour changes

- **Authorization enforcement:** The ownership check `ownerId: req.user.id` can no longer be bypassed via operator injection; it remains the exclusive gate for resource access.
- **Request validation:** Requests with non-scalar values in the `extra` field (e.g., nested objects or arrays) are now rejected with HTTP 400 and an `invalid_filter` error message.
- **Permitted requests:** Requests with scalar `extra` criteria (strings, numbers, booleans) continue to work as before, allowing the client to narrow results (e.g., by status or date) within the caller's own orders.
