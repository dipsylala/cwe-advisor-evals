## Verdict

SQL injection in ORDER BY clause due to direct string interpolation of unsanitized user input (`sortColumn` and `direction` parameters).

## Source

In `orderController.js`, user input from `req.query.sort` and `req.query.dir` is extracted without validation and passed directly to `findOrders()`. In `orderRepository.js` at line 8, these values are embedded directly into the SQL string using template literals: `` `ORDER BY ${sortColumn} ${direction}` ``, allowing an attacker to inject arbitrary SQL syntax.

## Fix

### File: orderRepository.js

```javascript
'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  // Whitelist allowed columns to prevent SQL injection
  const allowedColumns = ['id', 'total_cents', 'status', 'created_at'];
  const allowedDirections = ['ASC', 'DESC'];
  
  // Validate sortColumn against whitelist; default to safe value if invalid
  if (!allowedColumns.includes(sortColumn)) {
    sortColumn = 'created_at';
  }
  
  // Normalize direction to uppercase and validate; default to safe value if invalid
  const normalizedDirection = direction ? direction.toUpperCase() : 'DESC';
  if (!allowedDirections.includes(normalizedDirection)) {
    direction = 'DESC';
  } else {
    direction = normalizedDirection;
  }
  
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

Dynamic column names and sort directions cannot be safely parameterized in SQL prepared statements (parameterized queries only protect values, not identifiers or SQL keywords). The secure approach for ORDER BY clauses is to whitelist allowed values before interpolation.

The fix:
1. Defines `allowedColumns` and `allowedDirections` with legitimate values that correspond to the actual database schema and valid sort directions.
2. Validates `sortColumn` against the whitelist; if the supplied value is not allowed, defaults to `'created_at'`.
3. Normalizes `direction` to uppercase and validates it against `['ASC', 'DESC']`; if invalid, defaults to `'DESC'`.
4. Only after validation passes do we interpolate the values into the SQL string.

This ensures that even if an attacker supplies a malicious sort column or direction in the query parameters, the whitelist will reject it and substitute a safe default instead, preventing SQL injection.
