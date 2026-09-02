## Verdict

exploitable (confidence: high)

CWE-89 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').

## Source

`req.query.code` (Express query-string parameter `code` on `GET /orders/track`, `TemplateLiteralQueryConcat.js:14`) - attacker-controlled, no validation or encoding applied before use.

## Fix

Vulnerable code (`TemplateLiteralQueryConcat.js:16-19`):

```js
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
pool.query(sql, (err, rows) => {
```

Fixed code:

```js
const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

pool.execute(sql, [trackingCode], (err, rows) => {
```

The rest of the handler (error handling, `404`/`500` responses, `res.json(rows[0])`) is unchanged.

## Explanation

`trackingCode` reached the query as a literal string fragment inside a template literal, so an attacker could close the quoted value and inject arbitrary SQL (e.g. `' OR '1'='1`) to bypass the intended `WHERE` clause or run additional statements. The fix replaces the interpolated value with a `?` placeholder and passes `trackingCode` as a bound parameter, and switches the call from `pool.query()` to `pool.execute()` per the `mysql2` guidance: `query()` only interpolates placeholder values client-side through the driver's own escaping, while `execute()` sends the statement and the value separately as a true prepared statement, which is what actually eliminates the injection rather than just formatting it more safely. The value is now always treated as data, never as SQL structure.

## Behaviour changes

- Sink call changed from `pool.query(sql, cb)` to `pool.execute(sql, [trackingCode], cb)`. `mysql2`'s `execute()` accepts the same callback signature `(err, rows, fields)` and returns rows in the same `RowDataPacket[]` shape as `query()`, so `rows.length` and `rows[0]` behave identically; `execute()` additionally caches the prepared statement on the connection for reuse, which is a performance detail with no observable effect on the response.
- No other change: error handling (`err` -> `500`), the not-found (`404`) branch, and the successful `res.json(rows[0])` response are all preserved exactly as in the original.
