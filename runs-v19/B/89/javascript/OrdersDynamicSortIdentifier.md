## Verdict

Exploitable. The `sortColumn` and `direction` parameters flow from user-controlled HTTP query parameters (`req.query.sort` and `req.query.dir`) directly into SQL query string construction without validation, allowing an attacker to inject arbitrary SQL into the `ORDER BY` clause.

## Source

**orderController.js (lines 7-8):**
- `sortColumn = req.query.sort || 'created_at'` — attacker-controlled query parameter
- `direction = req.query.dir || 'DESC'` — attacker-controlled query parameter

**Call to vulnerable sink:**
- orderController.js line 10: `findOrders(req.db, accountId, sortColumn, direction)`

## Fix

### File: orderRepository.js

```javascript
'use strict';

// Whitelist of allowed column names
const ALLOWED_SORT_COLUMNS = {
  'id': 'id',
  'total_cents': 'total_cents',
  'status': 'status',
  'created_at': 'created_at'
};

// Whitelist of allowed directions
const ALLOWED_DIRECTIONS = {
  'ASC': 'ASC',
  'DESC': 'DESC'
};

async function findOrders(db, accountId, sortColumn, direction) {
  // Validate sortColumn against whitelist
  const validColumn = ALLOWED_SORT_COLUMNS[sortColumn];
  if (!validColumn) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }

  // Validate direction against whitelist
  const validDirection = ALLOWED_DIRECTIONS[direction];
  if (!validDirection) {
    throw new Error(`Invalid direction: ${direction}`);
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${validColumn} ${validDirection}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

SQL identifiers and keywords like column names and `ORDER BY` direction cannot be parameterized — they must be validated against a fixed server-side whitelist. The fix introduces two whitelists: `ALLOWED_SORT_COLUMNS` maps trusted column names to themselves, and `ALLOWED_DIRECTIONS` restricts direction to `ASC` or `DESC`. Before constructing the SQL query, the function now validates both `sortColumn` and `direction` against their respective whitelists, retrieving the canonical (trusted) value from the map rather than using the raw input. Only the validated values are interpolated into the query string, eliminating the injection vector. The parameterized query for `accountId` remains unchanged, preserving the layered defence-in-depth posture and the data-value parameter binding.

## Behaviour changes

**Added error throwing:** The function now throws an `Error` with a descriptive message if `sortColumn` or `direction` does not match the whitelist. The original code did not validate these inputs and would have silently constructed an invalid or injection-vulnerable query. Callers must now handle this thrown error; the orderController should catch it and return an appropriate HTTP error response (e.g., 400 Bad Request) to the client rather than executing the malformed query.

