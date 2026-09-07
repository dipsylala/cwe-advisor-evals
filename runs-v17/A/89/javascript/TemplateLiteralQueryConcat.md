## Verdict

CONFIRMED. The vulnerability is a SQL injection through unsanitized template literal interpolation. The `trackingCode` parameter from user input is inserted directly into the SQL query string without parameterization or escaping.

## Source

Line 16 constructs the SQL query by interpolating `trackingCode` directly into a template literal:

```
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
```

The value flows from untrusted user input at line 14:

```
const trackingCode = req.query.code;
```

And is consumed unsafely at line 19 in `pool.query(sql, ...)` where the database executes the concatenated string.

An attacker controlling `req.query.code` can supply SQL metacharacters (e.g., `' OR '1'='1`) to alter the query logic and return unauthorized data.

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

The fix replaces string concatenation with parameterized queries. Instead of interpolating the user input into the query string, a `?` placeholder marks the injection point, and the `trackingCode` is passed separately as an array argument to `pool.query()`. The mysql2 driver handles escaping and quoting at the protocol level, preventing the attacker from injecting SQL syntax. This is the standard defense against SQL injection in Node.js database libraries: separate query structure (the SQL template) from data (the parameter values), and let the driver enforce the boundary.
