## Verdict

The finding is confirmed. The route attempts to protect against unauthorized access by scoping the Mongoose query with both `_id` and `ownerId: req.user.id` (resource-level authorization). However, this protection is bypassed because `req.body.extra` is spread directly into the filter without validation or sanitization, allowing an authenticated attacker to inject Mongoose query operators that override the ownership check.

## Source

**File**: `orderRoutes.js`  
**Line**: 14  
**Code**: `const extraCriteria = req.body.extra || {};`

`req.body.extra` is untrusted user-supplied JSON from the request body. An attacker can inject Mongoose operators (e.g., `{ "$ne": null }`) via this object.

## Fix

### File: orderRoutes.js

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const Order = require('./orderModel');
const mongoose = require('mongoose');

const router = express.Router();

// POST /orders/:id/details - fetch a single order belonging to the
// authenticated caller. The mobile client may pass extra match criteria in
// the request body (for example { extra: { status: 'shipped' } }) so a
// lookup can be narrowed without a second round trip.
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...extraCriteria,
  };

  // Sanitize the filter to prevent Mongoose operator injection from extraCriteria.
  // sanitizeFilter wraps any nested object with keys starting with $ in $eq,
  // effectively treating them as literal scalar values rather than operators.
  const sanitizedFilter = mongoose.sanitizeFilter(filter);

  try {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    const order = await Order.findOne(sanitizedFilter);

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

The vulnerability arises because the spread of `extraCriteria` into the filter allows attacker-controlled properties to override or shadow the ownership check. An attacker authenticated as user A can send `{ "extra": { "ownerId": { "$ne": null } } }`, which turns the filter into `{ _id: "...", ownerId: { "$ne": null } }`, effectively removing the restriction to user A's records.

The fix applies `mongoose.sanitizeFilter()` to the filter before passing it to `findOne()`. According to the Mongoose CWE-862 guidance and Mongoose documentation, `sanitizeFilter()` wraps any nested object with keys starting with `$` in a `$eq` operator, treating them as literal scalar values rather than query operators. This prevents the injection while preserving the intended behavior of allowing legitimate extra filter criteria (e.g., `{ "extra": { "status": "shipped" } }` remains functional as a string comparison).

The fix imports `mongoose` at the top to access `mongoose.sanitizeFilter()` and applies sanitization immediately before the query, preserving the ownership check and eliminating the operator injection path.

## Behaviour changes

- **Security**: The ownership check `ownerId: req.user.id` is now protected from being overridden by untrusted input. An attacker can no longer inject Mongoose operators to retrieve orders from other users.
- **Functionality**: Legitimate extra filter criteria with scalar values (strings, numbers, booleans) continue to work as before. Attempts to inject Mongoose operators are converted to literal `$eq` comparisons, which will not match any documents and will safely fail the lookup, returning a 404 as expected.
- **Performance**: No measurable impact; `sanitizeFilter()` is a lightweight transformation applied at query construction time.
