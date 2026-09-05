## Verdict
exploitable

## Source
`req.query.code` (line 14) - untrusted user input from Express query parameter

## Sink
`pool.query(sql, ...)` (line 19) - SQL execution with concatenated query string

## Fix

### Vulnerable Code
```javascript
const trackingCode = req.query.code;
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
pool.query(sql, (err, rows) => {
```

### Fixed Code
```javascript
const trackingCode = req.query.code;
const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';
pool.execute(sql, [trackingCode], (err, rows) => {
```

## Explanation
The original code constructs SQL using a template literal with direct string interpolation, allowing an attacker to manipulate the query by providing input like `'; DROP TABLE orders; --`. The fix replaces string concatenation with parameterized query syntax using the `?` placeholder and passing `trackingCode` as a separate parameter array to `pool.execute()`. The `mysql2` library's `execute()` method prepares the statement on the server and sends parameter values separately, ensuring user input is always treated as data rather than executable SQL code. This eliminates the injection vector entirely regardless of input content.

## Behaviour changes
The call changes from `pool.query(sql, callback)` to `pool.execute(sql, [trackingCode], callback)`. The `execute()` method uses server-side prepared statements where `query()` uses client-side escaping, providing stronger protection against SQL injection. The callback signature and error handling remain identical, and the result rows are still returned in the same format. No other behaviour is affected.
