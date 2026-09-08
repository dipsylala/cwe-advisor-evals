## Verdict

This is a confirmed SQL injection vulnerability. The code constructs a SQL query by directly interpolating user-supplied input (`trackingCode`) into the query string via template literal syntax, then passes the concatenated string to `pool.query()`. An attacker can inject arbitrary SQL by providing a malicious value in the `code` query parameter, potentially bypassing authentication, extracting sensitive data, or modifying the database.

## Source

**File:** TemplateLiteralQueryConcat.js  
**Line:** 16 (vulnerability originates here) and 19 (sink where query executes)

Line 16 constructs the SQL query with direct string interpolation:
```
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
```

The variable `trackingCode` comes from untrusted user input (`req.query.code` on line 14) and is embedded directly into the SQL string without any parameterization or escaping. When this string is passed to `pool.query()` on line 19, it is executed as-is against the database.

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

  // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
  pool.query(sql, [trackingCode], (err, rows) => {
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

The fix replaces direct string interpolation with a parameterized query (prepared statement). Instead of embedding the user-supplied value directly into the SQL string, the query now uses a placeholder (`?`) and passes the parameters as a separate array argument to `pool.query()`.

**Key changes:**
- Line 16: Changed from `` `SELECT ... WHERE tracking_code = '${trackingCode}'` `` to `` `SELECT ... WHERE tracking_code = ?` ``
- Line 19: Changed from `pool.query(sql, (err, rows) => {...})` to `pool.query(sql, [trackingCode], (err, rows) => {...})`

The `mysql2` library's parameterized query mechanism ensures that the `trackingCode` value is properly escaped and treated as data, not as executable SQL syntax. This prevents an attacker from injecting SQL commands via special characters like quotes, semicolons, or SQL keywords in the tracking code parameter.
