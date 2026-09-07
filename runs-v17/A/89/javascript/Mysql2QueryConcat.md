## Verdict
CONFIRMED. Line 19 constructs an SQL query via string concatenation with unsanitized user input from `req.params.userId`. This allows an attacker to inject arbitrary SQL. The sink on line 23 executes the vulnerable query.

## Source
`req.params.userId` (line 15) is controlled by the attacker via the URL path parameter `:userId`.

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
Replace string concatenation with parameterized queries. The fix changes line 19 from `WHERE user_id = ${userId}` to `WHERE user_id = ?`, and passes `userId` as a parameter array to `pool.query()` on line 23: `pool.query(sql, [userId], ...)`. The `mysql2` driver automatically escapes and properly handles the parameter, preventing SQL injection. Parameterized queries are the primary defence against SQL injection in any language or database library.
