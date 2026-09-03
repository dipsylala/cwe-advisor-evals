## Verdict
SQL Injection via string concatenation in SQL query construction.

## Source
Line 19 directly interpolates the `userId` parameter into the SQL query using template literal syntax: `WHERE user_id = ${userId}`. The `userId` is obtained from `req.params.userId` without validation or escaping, creating an injection vector.

## Fix
Replace string interpolation with parameterized query placeholders:

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

  pool.query(sql, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to load orders' });
    }
    res.json({ orders: rows });
  });
});

module.exports = router;
```

## Explanation
Parameterized queries (prepared statements) separate SQL structure from user-supplied data. The `?` placeholder in line 19 indicates where a parameter value should be safely inserted. The second argument `[userId]` to `pool.query()` provides the values for placeholders. The database driver escapes and properly formats these values, preventing interpretation of SQL metacharacters as SQL syntax. This is the mysql2 library's standard and recommended method for safe query construction.
