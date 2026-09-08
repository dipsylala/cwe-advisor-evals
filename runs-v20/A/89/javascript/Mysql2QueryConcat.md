## Verdict

Confirmed. `req.params.userId` is concatenated directly into the SQL string via a template literal and passed to `pool.query()`, so a crafted `userId` path segment can alter the query's structure (classic SQL injection).

## Source

`req.params.userId` (route parameter `:userId` on `GET /api/users/:userId/orders`, line 15) — attacker-controlled, arrives as a string from the URL path.

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

The query string was built with a template literal that spliced `userId` straight into the `WHERE` clause, so any value other than a plain integer (e.g. `0 OR 1=1`, or a `UNION SELECT` payload) changes the query's logic or exfiltrates data from other tables.

`mysql2`'s `pool.query(sql, values, callback)` supports parameterized queries: the SQL text keeps a `?` placeholder in place of the interpolated value, and the actual value is passed separately in the `values` array. The driver sends the value out-of-band from the query text and applies its own escaping/type handling, so it can never be interpreted as SQL syntax regardless of its content — this removes the injection at the sink rather than trying to sanitize the input first. No other behavior changes: the query still filters on `user_id` and returns the same columns in the same order.
