## Verdict

VULNERABLE. The SQL query on line 16 uses a template literal to concatenate unsanitized user input directly into the query string, enabling SQL injection. The `trackingCode` parameter from `req.query.code` is embedded without parameterization, allowing an attacker to break out of the intended WHERE clause by injecting SQL syntax like `' OR '1'='1`.

## Source

Line 16 constructs the SQL query by interpolating `trackingCode` directly:
```
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
```

The `trackingCode` value originates from untrusted user input (`req.query.code` on line 14) and flows directly into the query string. Line 19 executes this unsafe SQL through `pool.query(sql, ...)`.

## Fix

Replace the template literal with a parameterized query using placeholder syntax:

```javascript
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
```

The `mysql2` library treats the `?` placeholder as a parameter marker and handles escaping automatically, ensuring the user input is treated as data, not executable SQL.

## Explanation

Template literal string interpolation provides no protection against SQL injection. The SQL query becomes a static string that the database server parses as executable code. By using parameterized queries with placeholders, the client library separates the SQL structure from the data, and the database server never interprets the parameter value as SQL syntax. This is the standard defense against SQL injection across all database drivers and languages.

