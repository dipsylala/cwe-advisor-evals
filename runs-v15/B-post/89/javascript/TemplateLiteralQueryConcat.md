## Verdict

Exploitable. The untrusted query parameter flows directly into SQL without parameterization, allowing an attacker to inject SQL commands.

## Source

`req.query.code` (line 14) - HTTP query parameter, user-controlled

## Fix

**Vulnerable code (line 14-19):**
```javascript
const trackingCode = req.query.code;

const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

pool.query(sql, (err, rows) => {
```

**Fixed code (line 14-19):**
```javascript
const trackingCode = req.query.code;

const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = ?`;

pool.execute(sql, [trackingCode], (err, rows) => {
```

## Explanation

The fix replaces the template-literal string concatenation with a parameterized query using the `?` placeholder. The untrusted `trackingCode` value is passed separately to `execute()` as an array element, ensuring the database driver treats it as data, not as executable SQL syntax. The `mysql2` library's `execute()` method prepares the statement on the server and sends parameter values separately, providing true statement preparation. Switching from `query()` to `execute()` is required because `query()` performs client-side interpolation through escaping (which fails against unquoted numeric contexts like `id = 1 OR 1=1`), while `execute()` sends parameters to the database server for proper parameterization.

## Behaviour changes

The callback signature and error handling remain identical - both `query()` and `execute()` use the same callback pattern `(err, rows) => {...}`, so no caller code changes. The only difference is how the parameter is transmitted: `query()` escapes and interpolates in the Node.js driver, while `execute()` sends the raw value to the server for native parameterization. This eliminates the injection risk without changing the API contract or application logic.
