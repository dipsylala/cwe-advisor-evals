## Verdict

**Confirmed SQL Injection (CWE-89)**. The code constructs a SQL query using template literal string interpolation with unsanitized user input from `req.query.code`, then executes it directly. An attacker can inject arbitrary SQL by supplying a `code` parameter containing SQL syntax, such as `' OR '1'='1` or `'; DROP TABLE orders; --`.

## Source

```javascript
// Line 16: SQL query built with template literal interpolation
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

// Line 19: Sink - query executed with unsanitized concatenated SQL
pool.query(sql, (err, rows) => {
```

The vulnerability path: attacker controls `req.query.code` (line 14) → used directly in template literal (line 16) → executed by `pool.query()` (line 19).

## Fix

Use parameterized queries with placeholders. The `mysql2` library supports `?` placeholders for parameter binding:

```javascript
router.get('/orders/track', (req, res) => {
  const trackingCode = req.query.code;

  // Use parameterized query with ? placeholder and parameter array
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

Template literal concatenation (`${variable}`) bypasses all SQL syntax protection — the database driver receives a fully formed SQL string with no way to distinguish user data from commands. Parameterized queries separate SQL structure from data: the `?` placeholder tells the driver where user input goes, and the parameter array `[trackingCode]` supplies the value. The driver then escapes and encodes the parameter correctly for SQL, making injection impossible even if the input contains quotes, comments, or SQL keywords.

This fix uses the same callback signature and flow, changing only the query construction and parameter passing method. No library changes are required — `mysql2` includes built-in parameterization support.
