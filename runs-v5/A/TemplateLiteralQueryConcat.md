## Verdict
Confirmed. `req.query.code` is concatenated directly into a SQL string via a template literal and passed to `pool.query`, allowing SQL injection.

## Source
`req.query.code` (line 14) — the customer-supplied `code` query-string parameter on `GET /orders/track`.

## Fix
```javascript
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
```

## Explanation
The original code builds the query with a JavaScript template literal, splicing `trackingCode` straight into the SQL text (`... WHERE tracking_code = '${trackingCode}'`). Because `mysql2`'s `pool.query()` treats whatever string it receives as the literal SQL to execute, any single quotes or SQL syntax in `code` become part of the command — an attacker can supply a value such as `' OR '1'='1` to bypass the intended filter, or use time-based/union-based payloads to extract data from other rows or tables.

The fix replaces the interpolated literal with a parameterized query: the SQL text keeps a `?` placeholder for the tracking code, and the actual value is passed separately in the values array as the second argument to `pool.query()`. `mysql2` sends the query and the parameter to the server independently, so the driver escapes and binds the value as data rather than as SQL syntax — the parameter can never change the shape of the query regardless of its contents. This is the standard, idiomatic defense for this driver and requires no additional input validation to be safe against injection (though validating `code`'s expected format, e.g. length/character set, remains good practice for input hygiene).
