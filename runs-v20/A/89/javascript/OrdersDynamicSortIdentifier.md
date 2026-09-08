## Verdict

Confirmed. `orderRepository.js` builds the `ORDER BY` clause by directly interpolating the client-controlled `sortColumn` and `direction` values into the SQL string. The `accountId` filter is correctly parameterized, but SQL placeholders can only bind values, not identifiers or keywords like column names or `ASC`/`DESC` - so the sort inputs bypass parameterization entirely and reach `db.execute()` as raw SQL text, allowing arbitrary SQL fragment injection via the `sort` and `dir` query parameters.

## Source

`req.query.sort` and `req.query.dir` in `orderController.js` (`listOrders`), passed unchanged as `sortColumn` and `direction` into `findOrders(req.db, accountId, sortColumn, direction)` in `orderRepository.js`, where they are interpolated into the `ORDER BY` clause at line 11's surrounding SQL build (the template literal above `db.execute`).

## Fix

### File: orderRepository.js
```javascript
'use strict';

const SORTABLE_COLUMNS = {
  created_at: 'created_at',
  total_cents: 'total_cents',
  status: 'status',
  id: 'id',
};

const SORT_DIRECTIONS = {
  ASC: 'ASC',
  DESC: 'DESC',
};

async function findOrders(db, accountId, sortColumn, direction) {
  const column = SORTABLE_COLUMNS[sortColumn] || SORTABLE_COLUMNS.created_at;
  const dir = SORT_DIRECTIONS[String(direction).toUpperCase()] || SORT_DIRECTIONS.DESC;

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${column} ${dir}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

SQL identifiers (column names) and keywords (`ASC`/`DESC`) cannot be supplied as bound parameters - drivers only escape and bind literal values, so a placeholder in the `ORDER BY` position would either be rejected or bound as a quoted string literal, breaking the query rather than securing it. Escaping or blocklisting the raw client string is also insufficient, since many SQL dialects support secondary injection vectors (e.g. backtick-quoted identifiers, comments, subqueries) that a hand-rolled sanitizer is likely to miss.

The fix instead resolves `sortColumn` and `direction` against two small, server-owned maps (`SORTABLE_COLUMNS`, `SORT_DIRECTIONS`) before they ever touch the SQL string. Only values that exactly match a known-safe key are used; anything else - including any attempted SQL fragment, comment sequence, or unrecognized column name - falls back to the safe default (`created_at DESC`), matching the documented default behavior in `orderController.js`. Because the interpolated `column` and `dir` values are now guaranteed to come from a fixed, developer-defined set of literal strings rather than from client input, the `ORDER BY ${column} ${dir}` template literal can no longer carry attacker-controlled SQL, while the `account_id = ?` filter continues to use proper parameter binding via `db.execute(sql, [accountId])`. The endpoint continues to support all originally intended sort keys and both directions; only inputs outside that allowlist are affected, and they are treated as "use the default" rather than rejected with an error, matching the existing lenient default-substitution behavior in the controller (`req.query.sort || 'created_at'`).
