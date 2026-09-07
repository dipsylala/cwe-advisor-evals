## Verdict
The SQL injection vulnerability is real and exploitable. The `trackingCode` parameter is sourced from untrusted user input (`req.query.code`), concatenated into the SQL query via a template literal without any sanitization, and passed directly to `pool.query()` for execution. An attacker can inject SQL metacharacters to manipulate the query logic.

## Source
Line 14: `const trackingCode = req.query.code;` - untrusted user input from request query parameter  
Line 16: `` const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`; `` - template literal builds SQL by string concatenation  
Line 19: `pool.query(sql, ...)` - concatenated SQL sent directly to database

## Fix
Replace string concatenation with parameterized queries using `pool.execute()` and placeholders.

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

  const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

  // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
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
The fix replaces the vulnerable template literal concatenation with a parameterized query using the `?` placeholder syntax. The key change is switching from `pool.query(sql)` to `pool.execute(sql, [trackingCode])`.

With `mysql2`, `query()` interpolates values client-side through escaping, which is bypassable. The `execute()` method sends a prepared statement to the server with placeholders, where parameter values are transmitted separately and cannot alter query structure. The database treats the parameter value as pure data, not executable SQL.

The `trackingCode` value is now passed in the array `[trackingCode]` as the second argument to `execute()`, never concatenated into the query string. This prevents SQL injection even if the input contains quotes, semicolons, or other SQL metacharacters.

## Behaviour changes
- The SQL statement is now prepared server-side before values are bound (vs. client-side string interpolation).
- Parameter values are transmitted separately from the query structure (vs. embedded in the query string).
- Database driver handles escaping at the protocol level (vs. JavaScript string escaping).
- Query execution is now atomic with parameter binding at the server, preventing structure manipulation.
- Performance is marginally improved due to server-side statement caching (prepared statements).
- Callback signature and error handling remain identical; the fix is transparent to calling code.
