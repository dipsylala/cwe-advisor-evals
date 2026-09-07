## Verdict
Exploitable

## Source
`req.body.extra` - user-controlled JSON object passed in request body (line 14)

## Fix

**Vulnerable code:**
```javascript
const extraCriteria = req.body.extra || {};

const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
  ...extraCriteria,
};

const order = await Order.findOne(filter);
```

**Fixed code:**
```javascript
const extraCriteria = req.body.extra || {};
const allowedFields = ['status'];
const sanitizedExtra = {};

// Only allow whitelisted fields with scalar values
for (const field of allowedFields) {
  if (field in extraCriteria && typeof extraCriteria[field] === 'string') {
    sanitizedExtra[field] = extraCriteria[field];
  }
}

const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
  ...sanitizedExtra,
};

const order = await Order.findOne(filter);
```

## Explanation
The vulnerability allows a malicious user to inject MongoDB operators into the filter by passing objects with keys prefixed with `$` in `req.body.extra`. For example, sending `{ extra: { $or: [{}] } }` would modify the query to match any order, bypassing the `ownerId` ownership check. The fix validates `extraCriteria` against a whitelist of allowed fields and ensures only scalar string values are spread into the filter. This prevents operator injection while maintaining the ability to narrow results by legitimate criteria like order status. The ownership check (`ownerId: req.user.id`) remains mandatory and cannot be bypassed by the filtered extra criteria.

## Behaviour changes
- Only fields in the `allowedFields` whitelist are accepted from `req.body.extra`; unwhitelisted fields are silently ignored
- Values in `extraCriteria` must be strings; any other type is rejected
- Query results will only include the authenticated user's orders matching both `_id` and `ownerId`, plus any allowed extra criteria
- No changes to the return value, error handling, or response codes
