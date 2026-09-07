## Verdict

SQL Injection confirmed. Untrusted `userId` parameter is interpolated directly into the SQL query string via template literal on line 17, then executed at the sink on line 23. User input reaches the SQL engine without parameterization, allowing an attacker to manipulate query logic.

## Source

`req.params.userId` (Express route parameter) flows to the SQL template literal on line 17:
```javascript
WHERE user_id = ${userId}
```

The sink is `pool.query(sql, callback)` on line 23, which executes the concatenated SQL.

## Fix

Replace the template literal with a parameterized query and use `pool.execute()` instead of `pool.query()`:

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

The fix eliminates the vulnerability by moving from client-side string interpolation to server-side parameterization. Three changes work together:

1. **Placeholder substitution** - Replace `${userId}` with `?` in the SQL string, converting it from executable code construction to a template that only specifies query structure.

2. **Method change** - Use `pool.execute()` instead of `pool.query()`. The `mysql2` library's `query()` method interpolates values client-side through its own escaping, which is bypassable (e.g., unquoted numeric contexts like `id = 1 OR 1=1`). The `execute()` method sends the query structure and values separately to the MySQL server, where the database engine binds the value as pure data, not as code.

3. **Value separation** - Pass `userId` as the second argument in an array `[userId]`, keeping it structurally isolated from the SQL syntax.

Together, these changes ensure the database engine always interprets `userId` as a data literal within the `WHERE` clause, not as a control structure that can alter query logic.

## Behaviour changes

None. The application returns the same result set. The only observable change is that the query is now parsed on the server side rather than the client side, and malicious input like `1 OR 1=1` is treated as a literal user ID value that will not match any row instead of being interpreted as a SQL boolean expression.
