## Verdict

Exploitable. CWE-89 (SQL Injection) confirmed at `TemplateLiteralQueryConcat.js` line 19.

## Source

`req.query.code` (line 14, `trackingCode`) - the `code` query-string parameter on `GET /orders/track`, fully attacker-controlled.

## Fix

### File: TemplateLiteralQueryConcat.js

```javascript
const express = require('express');
const mysql = require('mysql2');

const router = express.Router();
const pool = mysql.createPool({
  host: 'localhost',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  database: 'shop',
});

// Look up an order by the customer-supplied tracking code.
router.get('/orders/track', (req, res) => {
  const trackingCode = req.query.code;

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
});

module.exports = router;
```

## Explanation

`trackingCode` was spliced directly into the SQL text via a template literal, so any value containing a quote or SQL metacharacter (e.g. `' OR '1'='1`) altered the query's logic before it reached the driver. The fix replaces the interpolated string with a static query containing a `?` placeholder and passes `trackingCode` as a separate bound parameter. It also swaps `pool.query()` for `pool.execute()`: with `mysql2`, `query()` only interpolates placeholder values client-side through the driver's own escaping, whereas `execute()` sends the statement and the value separately as a real prepared statement, which is the parameterization the sink actually needs. `trackingCode` is now always treated as data, never as SQL structure.

## Behaviour changes

- `pool.query()` -> `pool.execute()`: required so the value is bound as a real prepared-statement parameter rather than client-side-escaped and re-interpolated; both methods on a `mysql2` pool return the same result-set shape and invoke the callback with the same `(err, rows)` signature, so the success and `err` handling paths, `res.json(rows[0])`, and the 404/500 responses are unchanged.
- SQL string changed from an interpolated literal to a static string with one `?` placeholder, with `trackingCode` moved into a bound-parameters array - this is the parameterization itself, not an incidental change.
- No other arguments, return handling, or error behaviour was added, removed, or altered.

## Verification

Ran `node --check` against the fixed file (copied to a scratch directory outside the repo, not the case fixture) - exit code 0, no syntax errors. `pool.execute()` is a documented `mysql2` `Pool`/`PoolConnection` method (the promise- and callback-based prepared-statement API mirrored from `Connection.execute()`), so no unverified API names were introduced. No other checker (e.g. a project test suite) was available in this context.
