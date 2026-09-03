## Verdict
exploitable

## Source
`req.body.extra` at line 14—attacker-controlled request body passed without validation into the query filter.

## Sink
`Order.findOne(filter)` at line 24—the filter object, constructed with untrusted `extraCriteria` spread into it, is executed as a database query.

## Fix

**Vulnerable code:**
```javascript
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...extraCriteria,  // Attacker can inject MongoDB operators here
  };

  try {
    const order = await Order.findOne(filter);
    // ...
  }
```

**Fixed code:**
```javascript
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  // Validate that extraCriteria contains only scalar values to prevent operator injection
  for (const [key, value] of Object.entries(extraCriteria)) {
    if (value !== null && typeof value === 'object') {
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
    // ...
  }
```

## Explanation
The vulnerability allows an attacker to bypass the ownership check by injecting MongoDB operators into the filter object. For example, sending `{"extra": {"ownerId": {"$ne": null}}}` would override the `ownerId: req.user.id` constraint, enabling queries for any order in the database. The guidance states: "A scoped filter only holds if the values in it are scalars. Mongoose's `sanitizeFilter` wraps any nested object whose key starts with `$` in a `$eq`; enable it, or coerce the identifier to a string before it reaches the filter, so a structured value cannot turn the predicate into an operator." The fix validates that each value in `extraCriteria` is a scalar (string, number, boolean, or null) before spreading it into the filter, preventing operator injection while preserving the intended narrowing of results for the authenticated user's own orders.

## Behaviour changes
The fix adds a validation check that rejects requests with nested objects or arrays in the `extra` parameter, returning a 400 Bad Request error. This preserves the intended filtering behavior for scalar values (e.g., `{"extra": {"status": "shipped"}}`) while blocking attempts to inject filter operators. The ownership scoping remains intact and cannot be bypassed.
