## Verdict

Exploitable. The ownership authorization check can be bypassed by client-supplied input.

## Source

`req.body.extra` (line 14) - client-supplied object in request body, stored as `extraCriteria`.

## Fix

**Vulnerable code (lines 14-20):**

```javascript
const extraCriteria = req.body.extra || {};

const filter = {
  _id: req.params.id,
  ownerId: req.user.id,
  ...extraCriteria,
};
```

**Fixed code:**

```javascript
const extraCriteria = req.body.extra || {};

const filter = {
  _id: req.params.id,
  ...extraCriteria,
  ownerId: req.user.id,
};
```

## Explanation

The vulnerability occurs because the object literal spreads `extraCriteria` (client-supplied) before assigning `ownerId` (server-controlled). In JavaScript object literals, when the same property key appears multiple times, the last assignment wins. An attacker can send `{ extra: { ownerId: "attacker_id" } }` in the request body, and the spread operator will set `ownerId` to the attacker's value, then the server's assignment of `ownerId: req.user.id` on line 18 is overridden by the spread on line 19. By moving the `ownerId` assignment to occur after the spread (last in the object literal), the server-controlled value cannot be overridden by client input, and the ownership check becomes enforceable. The lookup will now only return orders belonging to the authenticated user, eliminating the authorization bypass.

## Behaviour changes

None. The order of properties in a JavaScript object literal does not affect the runtime semantics of the filter object passed to Mongoose—only the final key-value pairs matter. Moving the `ownerId` assignment to last preserves the lookup contract (same fields, same values) while closing the authorization gap. The `Order.findOne(filter)` call on line 24 receives an identical filter structure with the same authorization guarantee.
