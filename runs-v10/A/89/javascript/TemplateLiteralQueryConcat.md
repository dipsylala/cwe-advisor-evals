## Verdict
SQL injection vulnerability confirmed. User-supplied input from `req.query.code` is concatenated directly into a SQL query string without parameterization, allowing arbitrary SQL command injection.

## Source
Line 14: `const trackingCode = req.query.code;` — untrusted input from query parameter.
Line 16: `const sql = \`SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'\`;` — template literal string interpolation embeds user input directly into SQL.
Line 19: `pool.query(sql, ...)` — vulnerable query executed against database.

## Fix
Replace the template literal concatenation with a parameterized query using `mysql2`'s placeholder syntax:

```javascript
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
```

## Explanation
The `mysql2` library supports parameterized queries where user input is passed as a separate array argument to `pool.query()`. The `?` placeholder is replaced with escaped values by the driver, ensuring that special characters in `trackingCode` are treated as data, not SQL syntax. This prevents injection attacks regardless of the input content.
