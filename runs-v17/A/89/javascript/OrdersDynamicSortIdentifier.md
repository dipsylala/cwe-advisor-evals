## Verdict
The code is vulnerable to SQL injection through unsanitized dynamic column names and sort direction. User-controlled input from query parameters is directly interpolated into the SQL statement via template literals without validation, allowing attackers to inject arbitrary SQL commands.

## Source
- **File**: orderRepository.js
- **Line**: 8
- **Vulnerability**: `ORDER BY ${sortColumn} ${direction}` uses template literal interpolation with untrusted input.
- **Data flow**: `req.query.sort` and `req.query.dir` in orderController.js → `sortColumn` and `direction` parameters → SQL injection sink in orderRepository.js

## Fix

### File: orderRepository.js
```javascript
'use strict';

const ALLOWED_COLUMNS = ['id', 'total_cents', 'status', 'created_at'];
const ALLOWED_DIRECTIONS = ['ASC', 'DESC'];

async function findOrders(db, accountId, sortColumn, direction) {
  // Validate sortColumn against whitelist
  if (!ALLOWED_COLUMNS.includes(sortColumn)) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }

  // Validate direction against whitelist
  if (!ALLOWED_DIRECTIONS.includes(direction.toUpperCase())) {
    throw new Error(`Invalid sort direction: ${direction}`);
  }

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

### File: orderController.js
```javascript
'use strict';

const { findOrders } = require('./orderRepository');

async function listOrders(req, res) {
  const accountId = req.user.accountId;
  const sortColumn = req.query.sort || 'created_at';
  const direction = req.query.dir || 'DESC';

  try {
    const orders = await findOrders(req.db, accountId, sortColumn, direction);
    res.json({ orders });
  } catch (error) {
    // Invalid sort parameters
    res.status(400).json({ error: error.message });
  }
}

module.exports = { listOrders };
```

## Explanation
The fix applies input validation using whitelisting, which is the standard defense for SQL injection when identifier names (column names, table names, sort direction) cannot be parameterized. 

**Key changes:**

1. **Whitelist allowed columns**: `ALLOWED_COLUMNS` defines the only column names that can be used in ORDER BY. This prevents injection through the `sortColumn` parameter.

2. **Whitelist allowed directions**: `ALLOWED_DIRECTIONS` restricts sort direction to `ASC` or `DESC`, preventing injection through the `direction` parameter.

3. **Validation before SQL construction**: Before the SQL statement is built, both parameters are validated against their respective whitelists. Invalid values throw an error immediately.

4. **Normalize direction**: The direction is normalized to uppercase to ensure consistent SQL and prevent case-sensitive bypass attempts.

5. **Error handling in controller**: The controller wraps the call in a try-catch block to return a user-friendly 400 Bad Request response when invalid parameters are provided, rather than exposing database errors.

This approach ensures that only known-safe identifiers and directions can be used in the SQL query, completely eliminating the SQL injection vulnerability while maintaining the application's functionality for legitimate sorting requests.
