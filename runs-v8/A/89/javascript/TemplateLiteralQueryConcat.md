## Verdict
True Positive

## Source
Line 14: `const trackingCode = req.query.code;` — unsanitized user input from query parameters

## Fix
Replace the template-literal concatenation with a parameterized query using placeholders:

```javascript
// Before (vulnerable):
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
pool.query(sql, (err, rows) => {

// After (safe):
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = ?`;
pool.query(sql, [trackingCode], (err, rows) => {
```

## Explanation
The vulnerability arises because `trackingCode` is interpolated directly into the SQL string using a template literal. An attacker can inject SQL metacharacters through `req.query.code` — for example, `' OR '1'='1` or `'; DROP TABLE orders; --` — to bypass the WHERE clause or alter the query structure entirely.

The fix uses `mysql2`'s parameterized query syntax. Passing `?` as a placeholder and the parameter value in an array causes the driver to treat the value as data, not executable SQL. The database layer safely escapes the value according to the dialect rules, preventing injection regardless of its content.
