## Verdict

Exploitable

## Source

`req.query.code` (line 14) - untrusted user input from query string parameter flows directly into the SQL query without sanitization.

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

  // Fixed: use pool.execute() with parameterized query
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

The vulnerability stems from line 16, where the SQL query is constructed using a template literal that directly interpolates the user-supplied `trackingCode` into the query string. This allows an attacker to inject SQL syntax by providing a malicious tracking code (e.g., `' OR '1'='1`), which would manipulate the query logic.

The fix replaces the template literal concatenation with a parameterized query using the `?` placeholder syntax and switches from `pool.query()` to `pool.execute()`. The `mysql2` library's `execute()` method sends parameter values separately from the SQL statement, ensuring they are always treated as data rather than executable SQL code. This is the primary defense against SQL injection: the database driver parses the SQL structure once with placeholders, then binds the parameter values separately, making it impossible for user input to alter the query's logic.

## Behaviour changes

Changed `pool.query(sql, callback)` to `pool.execute(sql, [trackingCode], callback)`. 

The `mysql2/mysql2` library's `execute()` method prepares the statement server-side and sends parameter values separately via the binary protocol, whereas `query()` interpolates values client-side. Both accept the same callback signature `(err, rows)` and return results in the same format, so the callback handler and response logic remain identical. The parameter array passed to `execute()` is matched positionally to the `?` placeholders in the SQL string. This change is necessary for parameterization to be enforced by the driver rather than relying on client-side escaping, which is insufficient against all injection attack vectors (unquoted numeric contexts, inline comments, encoding variations).
