## Verdict

CWE-89 (SQL Injection) confirmed. Untrusted user input from `req.query.code` is interpolated directly into an SQL query via template literal, then executed without parameterization. An attacker can supply a tracking code containing SQL syntax (e.g., `' OR '1'='1`) to manipulate the query logic.

## Source

Line 14: `const trackingCode = req.query.code;` — HTTP query parameter, untrusted.

Line 16: `const sql = \`SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'\`;` — template literal concatenates `trackingCode` directly into SQL.

Line 19: `pool.query(sql, (err, rows) => {` — sink executes the concatenated SQL.

## Fix

Replace lines 16-19 to use parameterized query with `pool.execute()`:

```javascript
const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';
pool.execute(sql, [trackingCode], (err, rows) => {
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

The fix replaces template literal concatenation with a parameterized query using `pool.execute()` and the `?` placeholder syntax. With `mysql2`, `execute()` prepares the statement on the server and sends values separately, preventing the database from interpreting user input as SQL syntax. The `trackingCode` is now passed as a bound parameter in the array `[trackingCode]`, ensuring it is always treated as data, not query structure. The callback signature and error handling remain identical, preserving the application logic while closing the injection vector.

## Behaviour changes

- Query execution now uses prepared statements (server-side parameterization via `execute()`) instead of client-side string interpolation.
- User input in the tracking code cannot alter query structure; SQL metacharacters are escaped automatically by the prepared statement protocol.
- No change to response logic, error handling, or callback signature.
- Performance impact is negligible; prepared statements in `mysql2` are optimized for pooled connections.
