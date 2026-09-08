## Verdict

Confirmed. `req.body.extra` is spread directly into the Mongoose filter object that is then passed to `Order.findOne()`. In the object literal `{ _id, ownerId, ...extraCriteria }`, `...extraCriteria` is written last, so a JavaScript object literal lets any `_id` or `ownerId` key inside it silently overwrite the route's own `req.params.id` / `req.user.id` values. Independently of that, Mongoose/MongoDB treats an object-valued field as an operator expression, so even a field name the caller cannot fully override can still be paired with an attacker-chosen operator value (e.g. `{ ownerId: { "$ne": null } }`, `{ ownerId: { "$exists": true } }`) to match orders that are not the caller's own. This is a missing-authorization flaw: the code intends to scope every lookup to the current user's own orders, but attacker-controlled input can widen or redirect that scope.

## Source

`req.body.extra` (client-supplied JSON body field `extra`), read at `orderRoutes.js:14` and merged unfiltered into the Mongoose filter at `orderRoutes.js:16-20`, which reaches the query sink `Order.findOne(filter)` at `orderRoutes.js:24`.

## Fix

### File: orderRoutes.js

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const Order = require('./orderModel');

const router = express.Router();

// Fields the mobile client is allowed to use to narrow an order lookup.
// Only scalar (string/number/boolean) values are accepted for these fields;
// object or array values are rejected outright so a caller cannot smuggle
// Mongo query operators (e.g. {"$ne": null}) into the filter, and neither
// _id nor ownerId can ever be supplied this way, so the caller can never
// widen or redirect the query away from their own order.
const ALLOWED_EXTRA_FIELDS = new Set(['status']);

function sanitizeExtraCriteria(extra) {
  const sanitized = {};

  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
    return sanitized;
  }

  for (const [key, value] of Object.entries(extra)) {
    if (!ALLOWED_EXTRA_FIELDS.has(key)) {
      continue;
    }
    if (value === null || typeof value === 'object') {
      // Rejects operator objects like {"$ne": null} and arrays.
      continue;
    }
    sanitized[key] = value;
  }

  return sanitized;
}

// POST /orders/:id/details - fetch a single order belonging to the
// authenticated caller. The mobile client may pass extra match criteria in
// the request body (for example { extra: { status: 'shipped' } }) so a
// lookup can be narrowed without a second round trip.
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = sanitizeExtraCriteria(req.body.extra);

  // _id and ownerId are set last so they can never be overridden by
  // extraCriteria, and extraCriteria itself is restricted to an allowlist
  // of scalar-valued fields above.
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

The original code built the filter as `{ _id, ownerId, ...extraCriteria }`, letting an attacker-controlled object both override the `_id`/`ownerId` scoping keys and inject Mongo comparison/logical operators as the *value* of any field (since Mongoose accepts `{ field: { "$ne": ... } }`, `{ "$gt": ... } }`, etc. as valid query shapes). Either avenue lets a caller retrieve or match orders outside their own ownership, which is the missing-authorization weakness.

The fix closes both avenues without changing the documented narrowing behavior for legitimate callers:

1. **Reserved fields can never be overridden.** `_id` and `ownerId` are written into `filter` last, from trusted server-side values (`req.params.id`, `req.user.id`) only — `extraCriteria` is spread first, so even if it somehow contained those keys they would be discarded by the following assignment order.
2. **Operator injection is blocked by a scalar check.** `sanitizeExtraCriteria` drops any key whose value is `null`, an object, or an array, so a value like `{ "$ne": null }` can never reach the query — Mongoose/MongoDB only interprets a field's value as an operator expression when that value is itself an object.
3. **The narrowing surface is an explicit allowlist**, not a denylist. Only `status` — an application-defined scalar field on the order document — passes through. This matches the feature the route already claims to support ("narrow a lookup" by additional match criteria) rather than exposing arbitrary query construction; extending the allowlist to another legitimate scalar field is a one-line change to `ALLOWED_EXTRA_FIELDS`.

A request that sends `{ "extra": { "status": "shipped" } }` continues to narrow the lookup exactly as before. A request that sends `{ "extra": { "ownerId": { "$ne": null } } }` or `{ "extra": { "_id": "someone-elses-id" } }` now has that entire key dropped before the filter is built, so the query still resolves to `{ _id: req.params.id, ownerId: req.user.id }` and the authorization boundary holds.
