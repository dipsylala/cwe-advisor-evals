## Verdict

Confirmed SQL Injection via template literal concatenation. The user-supplied `trackingCode` from `req.query.code` is interpolated directly into the SQL query on line 16 and executed on line 19 without parameterization. An attacker can manipulate the query logic, extract unauthorized data, or execute administrative operations by supplying input such as `' OR '1'='1`.

## Source

- **File**: TemplateLiteralQueryConcat.js
- **Source line 14**: `const trackingCode = req.query.code;` (user-controlled)
- **Sink line 16**: `const sql = \`SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'\`;` (direct template literal interpolation)
- **Execution line 19**: `pool.query(sql, (err, rows) => { ... })` (untrusted query executed)

## Fix

Replace the template literal concatenation with parameterized query syntax using `?` placeholders, pass the untrusted value as a separate parameter array, and switch from `pool.query()` to `pool.execute()` so the parameter is sent to the server separately rather than interpolated client-side.

**Vulnerable code (lines 16–19):**
```javascript
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

pool.query(sql, (err, rows) => {
```

**Fixed code:**
```javascript
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = ?`;

pool.execute(sql, [trackingCode], (err, rows) => {
```

## Explanation

The fix eliminates the concatenation injection point by moving the untrusted value out of the SQL string. The `?` placeholder tells the database driver to expect a value at that position, and the separate `[trackingCode]` array passes it to `pool.execute()`. With `mysql2`, `execute()` prepares the statement server-side and sends parameters separately, ensuring the database never interprets user input as query structure. Template literals and string concatenation are not secure alternatives and do not parameterize the query—only the prepared statement pattern with separate parameter binding closes this vulnerability.

## Behaviour changes

- **Query preparation**: The statement is now prepared once by the server (via `execute()`), improving performance for repeated queries.
- **Parameter binding**: The `trackingCode` value is bound as data, not interpolated as SQL—any special characters (quotes, semicolons, or SQL keywords) are treated as literal string content.
- **Output**: The callback signature remains unchanged; `rows` contains the same result set as before when the query succeeds.
- **Error handling**: On error, the callback receives the same error object. No change to error flow.
- **Database account privileges**: Remains unchanged; the fix does not alter the privilege model and should be paired with least-privilege database account setup as defence-in-depth.
