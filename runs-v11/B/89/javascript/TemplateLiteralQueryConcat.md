## Verdict

exploitable

## Source

`req.query.code` (line 14) — untrusted user-supplied query parameter

## Fix

**Vulnerable code (line 16):**
```javascript
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
```

**Fixed code:**
```javascript
const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';
pool.query(sql, [trackingCode], (err, rows) => {
```

Replace the template literal with a static SQL string containing a `?` placeholder, and pass the `trackingCode` value in a separate array as the second parameter to `pool.query()`. This separates query structure from data and ensures the value is always treated as a literal, not executable SQL.

## Explanation

The vulnerability occurs because `trackingCode` is directly interpolated into the SQL query string using a template literal. An attacker can supply a value like `' OR '1'='1` to manipulate the query logic and retrieve unauthorized records. The fix uses `mysql2`'s parameterized query support: the `?` placeholder marks where a value belongs, and the library handles escaping and binding at the driver level. This ensures user input is always treated as data, not query structure, preventing SQL injection regardless of the input content.

## Behaviour changes

The only change is the separation of the SQL string from the value parameter. The `pool.query()` callback signature and behavior remain identical — it receives the same three arguments (SQL statement/values/callback), and the error handling and result processing are unchanged. The query executes identically against the database when `trackingCode` contains normal input, and malicious payloads that would previously alter query logic now fail to parse or return no rows.
