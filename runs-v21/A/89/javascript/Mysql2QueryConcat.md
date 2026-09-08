## Verdict

Real.

## Source

Line 19: `userId` from `req.params` is unsanitized URL input. Lines 17–20 construct an SQL query string via template literal interpolation, embedding `userId` directly into the WHERE clause without parameterization.

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

  // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
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

The vulnerability is closed by replacing string interpolation with parameterized query placeholders. Line 19 changed from `WHERE user_id = ${userId}` to `WHERE user_id = ?`, and line 23 now passes `[userId]` as the second argument to `pool.query()`. The mysql2 driver separates the query template from its values, automatically escaping and properly typing the parameter so that SQL metacharacters in `userId` are treated as data, not command syntax.

