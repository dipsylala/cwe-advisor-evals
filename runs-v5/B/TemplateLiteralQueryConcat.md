## Verdict

Exploitable. `req.query.code` (attacker-controlled HTTP query parameter) reaches `pool.query()` by direct template-literal interpolation into a single-quoted SQL string context, with no validation or encoding in between. Confidence: high.

## Source

`req.query.code` in `router.get('/orders/track', ...)`, `TemplateLiteralQueryConcat.js` line 14.

## Fix

Vulnerable code (lines 14-19):

```javascript
const trackingCode = req.query.code;

const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

// SAST FINDING: CWE-89 ... Sink is the next statement.
pool.query(sql, (err, rows) => {
```

Fixed code:

```javascript
const trackingCode = req.query.code;

const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

pool.execute(sql, [trackingCode], (err, rows) => {
```

The rest of the callback body (lines 20-27) is unchanged.

## Explanation

The original code built the SQL statement by splicing `trackingCode` directly into a quoted string literal, so any value containing a `'` changes the query's structure rather than staying a data value - the classic tracking-code injection (`' OR '1'='1`, or a `UNION SELECT` to pull other orders). The fix replaces the interpolated literal with a static query and a `?` placeholder, and passes `trackingCode` as a bound parameter in the values array. Per this repository's `cwe/89/javascript` guidance, the call is also switched from `pool.query()` to `pool.execute()`: with `mysql2`, `query()` only applies its own client-side escaping to bound values even when placeholders are used, while `execute()` prepares the statement server-side and sends the parameter separately, so the value can never be reinterpreted as SQL syntax regardless of its content.

## Behaviour changes

- `pool.query()` -> `pool.execute()`: required by the fix itself (see Explanation); `execute()` returns rows in the same shape via the same `(err, rows)` callback signature, so the success and error branches below are unaffected.
- No other differences: the returned columns (`id, status, eta`), the 500/404/200 response handling, and the query's WHERE-clause semantics are all unchanged.
