## Verdict

exploitable (confidence: high)

- cwe_id: CWE-89
- location: `SequelizeRawQueryConcat.js`, line 20 (sink); construction at lines 12-17
- library_recommendation: none needed - `sequelize` is already the driver in use; the fix is a code-level change to the query call, not a dependency bump

## Source

`req.query.startDate` and `req.query.endDate` (lines 6-10) - both are raw, attacker-controlled HTTP query-string values. The only check applied is a presence check (`!startDate || !endDate`); neither value is validated as a date, escaped, or bound before use.

Data flow: `req.query.{startDate,endDate}` -> string-concatenated directly into the `WHERE order_date BETWEEN '...' AND '...'` clause (lines 15) -> `sequelize.query(sql, { type: QueryTypes.SELECT })` (line 20). No sanitization, allowlisting, or parameterization occurs anywhere on this path, so the trace confirms an exploitable path from source to sink (e.g. `startDate = "2024-01-01' OR '1'='1"` breaks out of the quoted literal and alters the query's logic).

Sink contract (`sequelize.query`): returns the raw row array for `QueryTypes.SELECT` (assigned to `rows` and returned as JSON - preserved by the fix); discards nothing beyond that; the `type` option is the only one supplied, everything else (`replacements`, `bind`, `raw`, transaction, logging) is left at its default (undefined/off), so adding a `bind` option is additive, not a change to an existing implicit argument; on failure it rejects the promise, which is unhandled here in both the original and fixed code (no behaviour change).

## Fix

### File: SequelizeRawQueryConcat.js

```javascript
const { QueryTypes } = require('sequelize');
const sequelize = require('../db/sequelize');

// GET /reports/orders?startDate=2024-01-01&endDate=2024-01-31
async function getOrderTotalsReport(req, res) {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: 'startDate and endDate are required' });
  }

  let sql =
    'SELECT customer_id, SUM(total_cents) AS total_cents ' +
    'FROM orders ' +
    'WHERE order_date BETWEEN $1 AND $2 ' +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  const rows = await sequelize.query(sql, {
    bind: [startDate, endDate],
    type: QueryTypes.SELECT,
  });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The query text no longer contains the attacker-controlled values. The `BETWEEN` bounds are replaced with positional bind placeholders (`$1`, `$2`), and `startDate`/`endDate` are passed through Sequelize's `bind` array so the underlying driver sends them as real query parameters rather than having Sequelize (or the developer) splice them into the SQL text. `bind` was chosen over Sequelize's `replacements` option because `replacements` performs client-side string substitution/escaping before the query is sent - the same class of manual-escaping defence the knowledge base flags as unreliable - whereas `bind` hands the values to the driver's native parameter binding, which keeps them uninterpretable as SQL structure regardless of content. No other part of the query (table, columns, `GROUP BY`, `ORDER BY`) is attacker-influenced, so no allowlisting is needed for this fix.

## Behaviour changes

- none - `rows` still receives the same `SELECT` result set via `QueryTypes.SELECT` and is returned via `res.json({ report: rows })` unchanged; only the two literal date bounds move from inline string concatenation to bound parameters, which is the mechanism closing the weakness, not an added behaviour.

## Verification

- `node --check` run against the fixed file (copied to a scratch location outside the repository, case files untouched): passed with no syntax errors.
- Manual check: `sequelize` and `QueryTypes` are the same imports as the original file (no new imports introduced). The `bind` option is documented Sequelize `query()` behavior (per the loaded language guidance) for passing an array of positional parameters matched to `$1`/`$2` placeholders in raw SQL, used here exactly as the guidance specifies - no unverified names introduced.

## Assumptions

- Assumed the target dialect supports Sequelize's dialect-agnostic `$1`/`$2` bind syntax (true for all dialects Sequelize supports for `bind`, per the loaded guidance); the database connection module (`../db/sequelize`) was not available to inspect for dialect confirmation, since it lives outside the case file.
