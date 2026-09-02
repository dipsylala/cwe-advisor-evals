## Verdict

Confirmed. `sortColumn` and `direction` are attacker-controlled request parameters that are concatenated directly into the SQL string used to build the `ORDER BY` clause, with no validation and no parameterization. Because SQL placeholders (`?`) can only bind literal values, not identifiers or keywords, the existing `db.execute(sql, [accountId])` parameterization does nothing to protect this part of the query. An attacker can inject arbitrary SQL via the `sort` or `dir` query parameters (e.g. subqueries, `UNION`-based extraction, or stacked/boolean payloads depending on the driver), independent of the `WHERE account_id = ?` binding.

## Source

- `req.query.sort` and `req.query.dir` in `orderController.js` (`listOrders`, lines 7-8) — untrusted, attacker-controlled HTTP query parameters, defaulted but not validated.
- Passed as `sortColumn` and `direction` into `findOrders(req.db, accountId, sortColumn, direction)` (line 10).
- In `orderRepository.js`, `findOrders` interpolates both directly into the SQL string via a template literal: `` `ORDER BY ${sortColumn} ${direction}` `` (line 8), which is then executed by `db.execute(sql, [accountId])` (line 11). Only `accountId` is bound as a parameter; `sortColumn` and `direction` become part of the raw SQL text.

## Fix

`orderRepository.js`:

```javascript
'use strict';

const SORTABLE_COLUMNS = new Set(['id', 'total_cents', 'status', 'created_at']);
const SORT_DIRECTIONS = new Set(['ASC', 'DESC']);

async function findOrders(db, accountId, sortColumn, direction) {
  const safeColumn = SORTABLE_COLUMNS.has(sortColumn) ? sortColumn : 'created_at';
  const safeDirection = SORT_DIRECTIONS.has(String(direction).toUpperCase())
    ? String(direction).toUpperCase()
    : 'DESC';

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${safeColumn} ${safeDirection}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

`orderController.js` is unchanged; it may keep passing `req.query.sort` and `req.query.dir` straight through, since `findOrders` now owns validation of these values before they reach SQL text. (Validating earlier, in the controller, and rejecting an invalid value with a 400 instead of silently falling back, is also reasonable — the requirement is that neither value reaches the SQL string unchecked, not which layer performs the check.)

## Explanation

`sortColumn` and `direction` select a column name and a keyword, not a value, so they cannot be passed as bind parameters the way `accountId` is — the driver's placeholder mechanism only quotes and escapes literals, and has no way to represent "an identifier" or "ASC/DESC" safely inside a placeholder. The only safe way to let user input influence an identifier or keyword position is to map the input to a fixed, known-safe set of options before it touches the query string, rather than trying to sanitize or escape the raw value.

The fix replaces the untrusted strings with a strict allowlist check (`SORTABLE_COLUMNS`, `SORT_DIRECTIONS`) against the exact column names the `orders` table exposes for sorting and the two valid SQL sort directions. Any value not in the allowlist falls back to a safe default (`created_at` / `DESC`) rather than being used verbatim, so no attacker-controlled substring ever reaches the `ORDER BY` clause. The `WHERE account_id = ?` binding is left as-is since it was already parameterized correctly. This closes the injection while preserving the sorting feature for all legitimate values the UI is expected to send.
