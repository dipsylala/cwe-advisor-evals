## Verdict

exploitable (confidence: high)

## Source

`req.body.extra` in `router.post('/orders/:id/details', ...)` (`orderRoutes.js:14`) - an authenticated but otherwise untrusted JSON object supplied entirely by the caller.

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

  // Caller-supplied extraCriteria is spread first, so any attempt to smuggle
  // an operator object under _id or ownerId (e.g. { ownerId: { $ne: null } })
  // is overwritten by the trusted values below rather than reaching Mongoose.
  const filter = {
    ...extraCriteria,
    _id: req.params.id,
    ownerId: req.user.id,
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

The handler builds a Mongoose filter as `{ _id, ownerId, ...extraCriteria }`, with the caller-controlled `extraCriteria` spread last. Since a later key in an object literal overwrites an earlier one, a request body such as `{ "extra": { "ownerId": { "$ne": null } } }` replaces the scalar `ownerId: req.user.id` with an operator object, turning the ownership predicate into "owner is not null" - any order in the collection then matches, regardless of who owns it. The same applies to `_id` via `{ "extra": { "_id": { "$ne": null } } }`, letting the caller enumerate arbitrary orders by supplying a `req.params.id` that doesn't even need to be valid. `Order.findOne()` never rejects a non-scalar filter value; it interprets it as a query operator, and `mongoose.sanitizeFilter()` (the guard against this) is never invoked anywhere in the app. The fix reorders the object literal so `_id: req.params.id` and `ownerId: req.user.id` are spread last: whatever keys `extraCriteria` contains, the trusted, scalar identifier and owner values always win and can never be replaced by an attacker-supplied operator object. `extraCriteria` may still narrow the match on any other field (e.g. `status`), which is the feature the route intends to offer, but it can no longer widen the match past the caller's own records.

## Behaviour changes

none - the sink (`Order.findOne`, same single argument, same returned document, same 404/200/500 response shape) is unchanged. The only change is the key order in the filter's object literal, which determines which value wins on a name collision; for any request that does not attempt to override `_id` or `ownerId`, the resulting filter is identical to before. `Order.findOne()`'s discarded output (no projection is specified, so the full document is returned and sent via `res.json(order)`) and its failure behaviour (thrown errors caught and mapped to a 500) are both unchanged.

## Verification

`node --check` against a copy of the fixed file in a scratch directory (outside the case directory) - passed with no syntax errors. No new imports, functions, or APIs were introduced; the only change is the ordering of three existing object keys, so no additional API-existence check was needed.
