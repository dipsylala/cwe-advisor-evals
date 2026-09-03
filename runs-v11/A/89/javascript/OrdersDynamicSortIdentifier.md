## Verdict

Confirmed SQL injection via unsanitized `ORDER BY` clause. The `sortColumn` and `direction` parameters originate from untrusted user input in `req.query` and are directly interpolated into the SQL query without validation.

## Source

**orderController.js (lines 7-8):**
```javascript
const sortColumn = req.query.sort || 'created_at';
const direction = req.query.dir || 'DESC';
```

**orderRepository.js (line 8):**
```javascript
`ORDER BY ${sortColumn} ${direction}`,
```

The values flow directly into the SQL query without any allowlisting or constraint checking.

## Fix

```javascript
// orderController.js
'use strict';

const { findOrders } = require('./orderRepository');

// Allowlist of safe columns
const ALLOWED_SORT_COLUMNS = ['id', 'total_cents', 'status', 'created_at'];
const ALLOWED_DIRECTIONS = ['ASC', 'DESC'];

async function listOrders(req, res) {
  const accountId = req.user.accountId;
  let sortColumn = req.query.sort || 'created_at';
  let direction = (req.query.dir || 'DESC').toUpperCase();

  // Validate sortColumn against allowlist
  if (!ALLOWED_SORT_COLUMNS.includes(sortColumn)) {
    sortColumn = 'created_at';
  }

  // Validate direction
  if (!ALLOWED_DIRECTIONS.includes(direction)) {
    direction = 'DESC';
  }

  const orders = await findOrders(req.db, accountId, sortColumn, direction);
  res.json({ orders });
}

module.exports = { listOrders };
```

## Explanation

The fix prevents SQL injection by enforcing an allowlist of permitted sort columns and directions before passing them to the query builder. Since `ORDER BY` identifiers cannot be parameterized, validation must occur in application code. The controller now:

1. Defines `ALLOWED_SORT_COLUMNS` and `ALLOWED_DIRECTIONS` as constants listing only safe values that match the actual database schema
2. Normalizes the direction to uppercase for consistent comparison
3. Validates user input against these allowlists, falling back to safe defaults if validation fails
4. Only passes validated values to the repository layer

This approach prevents attackers from injecting arbitrary SQL while maintaining the intended sorting functionality.
