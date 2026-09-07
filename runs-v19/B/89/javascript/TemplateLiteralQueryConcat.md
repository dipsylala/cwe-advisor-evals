## Verdict

Exploitable. Untrusted user input from the query parameter flows directly into a SQL query via template literal concatenation, allowing SQL injection.

## Source

User input enters via `req.query.code` (line 14) and flows without validation into a template literal that constructs the SQL query (line 16). This concatenated query is then executed by `pool.query()` at line 19.

An attacker can inject SQL by providing a malicious `code` parameter such as `' OR '1'='1` to manipulate the query logic.

## Fix

### File: TemplateLiteralQueryConcat.js

```javascript
const express = require('express');
const mysql = require('mysql2');

const router = express.Router();
const pool = mysql.createPool({
  host: 'localhost',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  database: 'shop',
});

// Look up an order by the customer-supplied tracking code.
router.get('/orders/track', (req, res) => {
  const trackingCode = req.query.code;

  const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = ?`;

  pool.execute(sql, [trackingCode], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'lookup failed' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'order not found' });
    }
    res.json(rows[0]);
  });
});

module.exports = router;
```

## Explanation

The fix eliminates SQL injection by replacing the template literal with a parameterized query. The SQL statement now uses `?` as a placeholder for the user input instead of interpolating the value directly into the string. The user input is passed separately as an array argument to `pool.execute()`, which sends it to the database server as a parameter rather than as SQL code. This ensures that `trackingCode` is always treated as data, never as executable SQL, regardless of its content. The switch from `pool.query()` to `pool.execute()` enables true server-side prepared statement handling in `mysql2`, providing the strongest protection against SQL injection.

## Behaviour changes

The change from `pool.query()` to `pool.execute()` affects how parameter binding occurs:
- `pool.query()` performs client-side parameter interpolation (escaping) before sending to the server
- `pool.execute()` sends the query and parameters separately to the server for true prepared-statement binding

Both methods accept the same callback signature `(err, rows)` and produce the same result set format, so the error handling and response logic remain functionally identical. This is a security upgrade with no adverse impact on application behavior.

The callback and return semantics are preserved: the method still accepts `(sql, [params], callback)` and the callback receives `(err, rows)` in the same format, so no downstream code changes are required.
