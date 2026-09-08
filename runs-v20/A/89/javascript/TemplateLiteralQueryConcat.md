## Verdict

Confirmed. The handler builds the SQL statement by interpolating the unvalidated `req.query.code` value directly into a template literal, then passes the resulting string to `pool.query()`. A tracking code such as `' OR '1'='1` (or one containing a closing quote plus additional SQL) alters the query's logic or structure, giving an attacker the ability to read arbitrary rows from the `orders` table or otherwise manipulate the query.

## Source

`req.query.code` (`trackingCode`) at line 14 of `TemplateLiteralQueryConcat.js` - an Express query-string parameter, fully attacker-controlled - flows unmodified into the template literal at line 16, which is passed as the SQL text to `pool.query()` at line 19.

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

  const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

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

The query text is now a fixed string with a `?` placeholder in place of the interpolated value, and `trackingCode` is passed separately in the parameter array. `mysql2` sends the value to the server through its prepared-statement/escaping mechanism rather than splicing it into the SQL text, so any quotes, comments, or SQL keywords the value contains are treated strictly as data for the `tracking_code` comparison and cannot change the query's structure. The rest of the handler - the connection pool setup, the error/not-found/success branching, and the response shapes - is unchanged, since only the query construction was the vulnerable element. A tracking code like `' OR '1'='1` now simply fails to match any row (falling into the 404 branch) instead of returning every order.
