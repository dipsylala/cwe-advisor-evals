## Verdict
Exploitable

## Source
`req.body.extra` (line 14) - attacker-controlled request body from client

## Fix

**Vulnerable code (line 13-24):**
```javascript
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...extraCriteria,
  };

  try {
    const order = await Order.findOne(filter);
```

**Fixed code:**
```javascript
router.post('/orders/:id/details', requireAuth, async (req, res) => {
  const extraCriteria = req.body.extra || {};

  // Allowlist: only permit safe, non-authorization-critical criteria
  const allowedKeys = ['status'];
  const filteredExtra = {};
  for (const key of allowedKeys) {
    if (key in extraCriteria) {
      filteredExtra[key] = extraCriteria[key];
    }
  }

  const filter = {
    _id: req.params.id,
    ownerId: req.user.id,
    ...filteredExtra,
  };

  try {
    const order = await Order.findOne(filter);
```

## Explanation
The vulnerability arises from spreading untrusted request data directly into the filter object. An authenticated attacker can send `{ "extra": { "ownerId": "victim-id" } }` to override the authorization check on line 18, retrieving another user's order. The fix uses an allowlist to constrain which keys from the request body are permitted to flow into the filter, preventing an attacker from injecting authorization-critical fields like `ownerId`. Only scalar values matching the documented allowlist (e.g., `status`) are included; the ownership check remains in server control and cannot be bypassed via request data.

## Behaviour changes
None. The filter still accepts the same optional `status` parameter from the client as originally intended (line 11), but now rejects attempts to override `ownerId`, `_id`, or any other critical field. The query scope—ownership-gated access to a specific record—is preserved and hardened.
