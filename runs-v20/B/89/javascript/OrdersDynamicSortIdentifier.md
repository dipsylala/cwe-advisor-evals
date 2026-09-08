## Verdict

Confirmed. `orderRepository.js` builds the `ORDER BY` clause of a SQL statement by interpolating `sortColumn` and `direction` directly into the query string with no validation, allowing an attacker to inject arbitrary SQL through those two request-controlled fields.

## Source

`orderController.js` (`listOrders`) reads `sortColumn` from `req.query.sort` and `direction` from `req.query.dir` - both are unauthenticated, attacker-controlled HTTP query-string values (falling back to `'created_at'` / `'DESC'` only when absent, which does not constrain a supplied value). These are passed straight through to `findOrders(req.db, accountId, sortColumn, direction)` with no validation at the controller.

## Fix

### File: orderRepository.js
```javascript
'use strict';

const ALLOWED_SORT_COLUMNS = new Map([
  ['id', 'id'],
  ['total_cents', 'total_cents'],
  ['status', 'status'],
  ['created_at', 'created_at'],
]);

const ALLOWED_DIRECTIONS = new Map([
  ['ASC', 'ASC'],
  ['DESC', 'DESC'],
]);

const DEFAULT_SORT_COLUMN = 'created_at';
const DEFAULT_DIRECTION = 'DESC';

async function findOrders(db, accountId, sortColumn, direction) {
  const column = ALLOWED_SORT_COLUMNS.get(sortColumn) || DEFAULT_SORT_COLUMN;
  const dir = ALLOWED_DIRECTIONS.get(String(direction).toUpperCase()) || DEFAULT_DIRECTION;

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

`sortColumn` and `direction` occupy identifier/keyword positions in the SQL text (a column name and an `ASC`/`DESC` keyword), not value positions, so they cannot be fixed by binding them as parameters to `db.execute` - only the existing `accountId` placeholder is eligible for that, and it was already correctly parameterized. The fix instead treats both fields as keys into a fixed, server-defined allowlist (`ALLOWED_SORT_COLUMNS`, `ALLOWED_DIRECTIONS`) built from the columns the query itself selects (`id`, `total_cents`, `status`, `created_at`) and the two valid sort directions. The value that reaches the query is always the map's own canonical string, never the caller-supplied one - a request value that is not an exact key falls back to the same defaults the controller already used for a missing value (`created_at` / `DESC`), so no attacker-influenced text ever reaches the `ORDER BY` clause, whether or not it happens to match a legitimate column name. `direction` is uppercased before lookup so lowercase query values (`?dir=asc`) keep working. The `WHERE account_id = ?` placeholder and the parameter array are unchanged, preserving the existing parameterized filter.

## Behaviour changes

- A `sort` or `dir` value that is not one of the four known columns or `ASC`/`DESC` (case-insensitive) now silently falls back to `created_at` / `DESC` instead of being passed to the database. Previously such a value either produced attacker-controlled query behaviour or a SQL error from the driver; it can no longer do either.
- No change for any request already using a legitimate value (`id`, `total_cents`, `status`, `created_at`, and `ASC`/`DESC` in any case) - those continue to sort exactly as before.
- Return value, error behaviour on a valid query, and the `WHERE account_id = ?` filtering are unchanged.

Verified with `node --check` against the fixed file in isolation (syntax only; no project test runner was available in this context).
