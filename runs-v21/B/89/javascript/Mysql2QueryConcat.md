## Verdict
Fixed: SQL injection vulnerability eliminated by converting concatenated query to parameterized prepared statement using mysql2's `execute()` method.

## Source
Data flows from `req.params.userId` (line 15) into the template literal at lines 17-20, where it is directly interpolated as `${userId}` into the SQL string. This concatenated SQL is then passed to `pool.query()` at line 23, making it vulnerable to SQL injection.

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

  // Fixed: Using parameterized query with execute() for true server-side preparation.
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
The vulnerability was SQL string concatenation: `${userId}` embedded directly into the SQL query template literal. An attacker can submit `userId` as `1 OR 1=1` or similar, modifying query logic and bypassing security.

The fix uses mysql2's `execute()` method with parameterized queries. The placeholder `?` marks where a parameter value goes, and the library passes `[userId]` separately to the database server. The database driver then safely escapes and binds the parameter client-side before sending to the server, guaranteeing the value is always treated as data, not executable SQL syntax. This approach is resistant to all forms of SQL injection, including numeric contexts and bypasses that defeat keyword-based filtering.

## Behaviour changes
- `pool.query(sql, [params], callback)` with concatenated SQL → `pool.execute(sql, [params], callback)` with placeholder syntax
- Query parameter binding moves from implicit (via escaping through string concatenation) to explicit server-side preparation
- Performance is neutral or improved due to statement caching on the database server
- No functional changes to the API or response contract; requests return the same data with the same JSON schema
