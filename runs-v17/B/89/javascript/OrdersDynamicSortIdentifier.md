## Verdict
Exploitable

## Source
Untrusted user input from HTTP query parameters in `orderController.js`:
- `req.query.sort` assigned to `sortColumn` (line 7, defaults to 'created_at')
- `req.query.dir` assigned to `direction` (line 8, defaults to 'DESC')

These values flow directly to `findOrders()` and are concatenated into the SQL query without validation.

## Fix

### File: orderRepository.js

```javascript
'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  // Allowlist of permitted columns for sorting
  const permittedColumns = ['id', 'total_cents', 'status', 'created_at'];
  // Allowlist of permitted sort directions
  const permittedDirections = ['ASC', 'DESC'];

  // Validate sortColumn against allowlist
  if (!permittedColumns.includes(sortColumn)) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }

  // Validate direction against allowlist
  if (!permittedDirections.includes(direction.toUpperCase())) {
    throw new Error(`Invalid sort direction: ${direction}`);
  }

  // Use validated values in SQL query - these are now trusted
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction.toUpperCase()}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation
The vulnerability existed because `sortColumn` and `direction` query parameters were interpolated directly into the SQL query via template literals on line 8, bypassing the parameterization used for the `accountId` value. An attacker could inject SQL fragments through these parameters. The fix adds server-side allowlist validation for both the sort column and direction before constructing the query. Only values that match the permitted allowlist ('id', 'total_cents', 'status', 'created_at' for columns and 'ASC', 'DESC' for direction) are accepted; others trigger an error. The validated values are then safe to use in the query construction because they are constrained to a fixed set of application-controlled identifiers.

## Behaviour changes
- Function now throws an `Error` if an invalid `sortColumn` is provided (one not in the allowlist), when previously it would silently accept any value and potentially allow SQL injection.
- Function now throws an `Error` if an invalid `direction` is provided (one not in the allowlist), when previously it would accept any value.
- The `direction` parameter is normalized to uppercase before use in the query (e.g., 'desc' becomes 'DESC'), ensuring case-insensitive matching against the allowlist while maintaining consistent SQL formatting.
- All other behavior is preserved: the query still filters by `accountId` using parameterization, returns the same column set, and maintains the same result structure.
