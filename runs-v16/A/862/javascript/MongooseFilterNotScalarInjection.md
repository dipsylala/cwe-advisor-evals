## Verdict
CONFIRMED — Authenticated user can override authorization check via request body.

## Source
The vulnerability lies in line 19, where user-supplied `extraCriteria` is spread into the filter object after `ownerId` is set. Since JavaScript object spread uses the last assignment for duplicate keys, an attacker can provide `{ extra: { ownerId: <different-user-id> } }` in the request body to override the authorization check and access another user's order.

## Fix
```javascript
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  // Allowlist of safe filter fields the client may provide
  const ALLOWED_FILTER_FIELDS = ['status', 'total', 'createdAt'];
  const extraCriteria = req.body.extra || {};

  // Validate and whitelist allowed fields only
  const safeExtraCriteria = {};
  for (const key of ALLOWED_FILTER_FIELDS) {
    if (key in extraCriteria) {
      safeExtraCriteria[key] = extraCriteria[key];
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
```

## Explanation
The original code allowed arbitrary fields from `req.body.extra` to override the authorization-critical `ownerId` field in the filter. The fix implements an allowlist (`ALLOWED_FILTER_FIELDS`) that explicitly defines which fields the client is permitted to filter by. Only fields in this allowlist are copied into `safeExtraCriteria`, which prevents an attacker from injecting `ownerId` or other sensitive fields. The authorization check is now guaranteed because `ownerId: req.user.id` cannot be overridden by user input.
