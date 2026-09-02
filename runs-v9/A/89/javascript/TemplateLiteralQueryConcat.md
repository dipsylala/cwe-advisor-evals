## Verdict

Confirmed. The `tracking_code` lookup builds its SQL statement by interpolating `req.query.code` directly into a template literal, then passes the resulting string to `pool.query()`. A request such as `/orders/track?code=' OR '1'='1` (or a payload using `UNION SELECT`, stacked queries, etc.) is executed as SQL rather than treated as data, giving an attacker read access to arbitrary rows or columns in the `orders` table and a foothold toward the rest of the database.

## Source

`req.query.code` (the `code` query-string parameter on `GET /orders/track`), read at line 14 into `trackingCode`.

## Fix

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

The fix replaces string interpolation with a parameterized query: the SQL text now contains a literal `?` placeholder instead of the tracking code, and the value is passed separately as the second argument to `pool.query()`. `mysql2` sends the statement and the parameter to the server independently, so the driver escapes and binds `trackingCode` as a single string value for the `tracking_code` column rather than as SQL syntax — any quotes, comment markers, or keywords in the input are treated as inert data, not part of the query structure. This closes the injection at its source without changing the route's behavior for legitimate tracking codes, and it generalizes to any additional user-supplied filters added to this query later, as long as each one is passed through its own placeholder rather than concatenated into the SQL string.
