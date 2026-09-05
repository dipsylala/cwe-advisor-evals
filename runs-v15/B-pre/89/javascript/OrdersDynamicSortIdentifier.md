## Verdict

Exploitable. Untrusted query parameters flow directly into SQL query construction without validation.

## Source

HTTP query parameters `sort` and `dir` from `orderController.js` (lines 7-8):
- `const sortColumn = req.query.sort || 'created_at'`
- `const direction = req.query.dir || 'DESC'`

These are passed to `findOrders()` and interpolated into the SQL query without allowlist validation.

## Fix

**orderController.js:**

```javascript
'use strict';

const { findOrders } = require('./orderRepository');

// Allowlist of permitted column names
const ALLOWED_SORT_COLUMNS = {
  created_at: 'created_at',
  id: 'id',
  total_cents: 'total_cents',
  status: 'status'
};

// Allowlist of permitted sort directions
const ALLOWED_DIRECTIONS = {
  ASC: 'ASC',
  DESC: 'DESC'
};

async function listOrders(req, res) {
  const accountId = req.user.accountId;
  const sortColumn = ALLOWED_SORT_COLUMNS[req.query.sort] || ALLOWED_SORT_COLUMNS.created_at;
  const direction = ALLOWED_DIRECTIONS[req.query.dir] || ALLOWED_DIRECTIONS.DESC;

  const orders = await findOrders(req.db, accountId, sortColumn, direction);
  res.json({ orders });
}

module.exports = { listOrders };
```

**orderRepository.js:**

No changes required. The function now receives only allowlist-validated values.

## Explanation

The vulnerability exists because `sortColumn` and `direction` from user query parameters are interpolated directly into the SQL `ORDER BY` clause using template literals. An attacker can inject arbitrary SQL by crafting malicious query parameters like `?sort=id;DROP TABLE orders--`.

The fix implements strict allowlist validation in the controller layer before the values reach the repository. The controller defines fixed maps of permitted column names and sort directions, then looks up the user-supplied values against these maps. Only the canonical values from the allowlist are passed to the repository function, never the raw user input. This ensures that no matter what the attacker sends, only predefined SQL identifiers can reach the query.

The `||` operators provide safe defaults (`created_at` and `DESC`) when the user provides an unrecognized value or omits the parameter entirely.

## Behaviour changes

**In orderController.js:**
- Added `ALLOWED_SORT_COLUMNS` and `ALLOWED_DIRECTIONS` objects to define the permitted set of identifiers and directions.
- Changed the assignment of `sortColumn` and `direction` to look up values in the allowlists instead of using user input directly. Supplies defaults (`created_at` and `DESC`) for unrecognized values.

**Reason:** Identifiers (column names, sort directions) cannot be parameterized in SQL and must be validated against a fixed allowlist of permitted values. This prevents any arbitrary SQL injection while maintaining the intended functionality of allowing the user to select from a predefined set of sort options.

**In orderRepository.js:**
- No changes. The function continues to receive and use the column name and direction as before, but now they are guaranteed to be from the allowlist.

**Impact:** Users can no longer provide arbitrary column names or directions; only the whitelisted options (`created_at`, `id`, `total_cents`, `status` for columns; `ASC`, `DESC` for directions) are accepted. Unrecognized values silently fall back to the defaults, which is typical UI behavior for filtering controls.
