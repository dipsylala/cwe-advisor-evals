## Verdict

Exploitable. The vulnerability is a confirmed SQL injection in the database query handler. User-supplied `userId` from request parameters is directly concatenated into the SQL query without parameterization, allowing attackers to inject arbitrary SQL.

## Source

`userId` extracted from `req.params` at line 15, attacker-controlled via URL path parameter.

## Fix

### File: Mysql2QueryConcat.js

```javascript
const express = require('express');
const mysql = require('mysql2');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Returns the order history for a given customer.
router.get('/api/users/:userId/orders', (req, res) => {
  const { userId } = req.params;

  const sql = `SELECT id, item, quantity, total_cents, created_at
               FROM orders
               WHERE user_id = ?
               ORDER BY created_at DESC`;

  // Fixed: use execute() with parameterized query
  pool.execute(sql, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to load orders' });
    }
    res.json({ orders: rows });
  });
});

module.exports = router;
```

## Explanation

The original code built the SQL query using template literal string interpolation (`${userId}`), which treats the user input as SQL code rather than data. This allows attackers to inject SQL syntax—for example, a `userId` of `1 OR 1=1 --` bypasses the WHERE clause and returns all orders.

The fix replaces `pool.query()` with `pool.execute()` and converts the SQL to use a `?` placeholder for the `userId` parameter. The value is passed separately in an array as the second argument: `[userId]`. The `mysql2` library's `execute()` method sends the placeholder and value to the server, which handles parameterization server-side, ensuring the user input is always treated as data, not executable SQL syntax. This is the only way `mysql2` enforces true parameterization; the legacy `query()` method interpolates values client-side using the library's escape function, which does not provide the same level of protection.

## Behaviour changes

1. **Method changed from `query()` to `execute()`**: The original code used `pool.query(sql, callback)`. The fixed code uses `pool.execute(sql, [values], callback)`. This is a required change for `mysql2` to apply server-side parameterization. The `execute()` method prepares the statement server-side and binds parameters separately, whereas `query()` interpolates values client-side. The callback signature remains the same (err, rows), so no downstream code changes are needed.

2. **Placeholder syntax**: The SQL template literal was changed from `${userId}` to `?`. This is required to mark the parameter position for binding.

3. **Parameter passing**: The fix adds an array `[userId]` as a second argument to the execute call. This provides the values to bind to the placeholders. The original code had no explicit parameter argument.

No other behaviour is altered. The query still returns the same result set, the error handling remains identical, and the response format is unchanged.
