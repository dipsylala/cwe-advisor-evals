## Verdict
**CONFIRMED** - CWE-862 (Missing Authorization)

## Source
Lines 14-20 construct an unvalidated database filter by spreading user-supplied request body data directly into the query filter alongside authorization-critical fields. Line 24 executes the compromised query.

```javascript
const extraCriteria = req.body.extra || {};

const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
  ...extraCriteria,
};

const order = await Order.findOne(filter);
```

The spread operator on line 19 allows an attacker to override authorization-critical fields. An attacker can provide `{ extra: { ownerId: "victim-id" } }` in the request body to inject a competing `ownerId` value that shadows the legitimate one set on line 18, or inject new filter fields entirely to broaden the query scope.

## Fix
Reject untrusted input into filter fields. Validate and allowlist any extra criteria the client is permitted to supply, then merge only the whitelisted fields:

```javascript
const allowedCriteria = {};
if (req.body.extra && req.body.extra.status) {
  // Validate status against a known set of values
  const validStatuses = ['pending', 'shipped', 'delivered'];
  if (validStatuses.includes(req.body.extra.status)) {
    allowedCriteria.status = req.body.extra.status;
  }
}

const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
  ...allowedCriteria,
};

const order = await Order.findOne(filter);
```

Alternatively, if no extra criteria should be permitted, remove the spread entirely:

```javascript
const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
};

const order = await Order.findOne(filter);
```

## Explanation
The endpoint is documented to fetch an order belonging to "the authenticated caller," but the authorization check is bypassable. Directly spreading unvalidated request body data into a Mongoose query filter allows an attacker to inject additional filter clauses that override ownership checks or change query semantics entirely.

The fix requires that any user-supplied filter fields be explicitly validated against a whitelist of permissible field names and their acceptable values before inclusion in the query. This ensures that authorization-critical fields like `ownerId` cannot be shadowed or rewritten by the client.
