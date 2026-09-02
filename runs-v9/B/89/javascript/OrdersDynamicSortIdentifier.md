## Verdict

- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command / SQL Injection)
- **Location**: `orderRepository.js`, `findOrders()`, line 11 (`db.execute(sql, [accountId])`) - the query text built at line 8 is unsafe by the time it reaches this call
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `req.query.sort` and `req.query.dir` in `orderController.js` (`listOrders`, lines 7-8) - attacker-controlled HTTP query parameters, defaulted only when absent (`|| 'created_at'`, `|| 'DESC'`) and otherwise passed through unchanged.
- **Path**: `listOrders()` passes `sortColumn` and `direction` straight into `findOrders(req.db, accountId, sortColumn, direction)` with no validation at the controller.
- **Sink**: `orderRepository.js` line 8 interpolates both values directly into the SQL text via a template literal: `` `ORDER BY ${sortColumn} ${direction}` ``. That string is then executed at line 11 via `db.execute(sql, [accountId])`. `accountId` is correctly bound as a placeholder parameter, but `sortColumn`/`direction` sit in an identifier/keyword position that a placeholder cannot cover, so they reach the database as raw SQL text. A payload such as `sort=id; DROP TABLE orders;--` or `dir=ASC; <malicious>` is not neutralized anywhere on this path.
- **Sink contract** (`db.execute`, `mysql2`-style):
  - **Returns**: `[rows, fields]`; the code destructures `rows` and returns it to the controller, which serializes it as `{ orders }` JSON.
  - **Discards**: the `fields` metadata array (unrelated to this fix).
  - **Implicit arguments**: none beyond the two positional arguments; no query options object is used.
  - **Failure behaviour**: `findOrders` and `listOrders` are both `async` with no `try/catch`; a DB error (e.g. a syntax error from a malformed `ORDER BY`) rejects the promise and propagates to whatever wraps the Express handler (default error handling, since none is visible in this chain).

## Fix

No third-party library change is needed; the fix is allowlist validation at the point the identifier enters the query, per `cwe/89/javascript/INDEX.md` ("Placeholders stand in for values, not for structure... a table name, column name, or `ORDER BY` direction cannot be bound").

Vulnerable code (`orderRepository.js`):

```javascript
'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`, // sortColumn/direction are unvalidated request input
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

Fixed code (`orderRepository.js`):

```javascript
'use strict';

// Server-side map: only these client-facing names may select a sort column,
// and the query only ever sees the mapped, trusted column name on the right.
const SORT_COLUMNS = {
  id: 'id',
  total: 'total_cents',
  status: 'status',
  created_at: 'created_at',
};

const SORT_DIRECTIONS = new Set(['ASC', 'DESC']);

async function findOrders(db, accountId, sortColumn, direction) {
  const column = SORT_COLUMNS[sortColumn];
  if (!column) {
    throw new Error('Invalid sort column requested');
  }

  const normalizedDirection = String(direction).toUpperCase();
  if (!SORT_DIRECTIONS.has(normalizedDirection)) {
    throw new Error('Invalid sort direction requested');
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${column} ${normalizedDirection}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

`ORDER BY` column and direction are structural SQL, not values, so `db.execute`'s placeholder (`?`) cannot bind them - that gap is exactly what let `sortColumn`/`direction` reach the query as raw text. The fix closes it by never letting the caller's string reach the SQL: `sortColumn` is looked up in `SORT_COLUMNS`, a fixed, server-defined map from the small set of client-facing sort names to the real column names the table actually exposes for sorting, and the query is built from the map's value, not the request's. `direction` is normalized to uppercase and checked against a two-value allowlist (`ASC`/`DESC`) before use. Any input outside those sets is rejected before it ever becomes part of the SQL string, so no payload placed in `sort` or `dir` can alter the query's structure. `accountId` was already correctly parameterized and is untouched.

## Behaviour changes

- **New failure path for invalid `sort`/`dir` values**: previously an unrecognized `sortColumn`/`direction` (whether malicious or simply a typo) was concatenated straight into the SQL and either executed as-is or produced a raw database syntax error. Now `findOrders` throws a plain `Error` before any query runs. `listOrders` (in `orderController.js`, not modified here since it is outside the fixture's flagged file but relevant to callers) has no `try/catch`, so this error will propagate the same way a rejected `db.execute()` promise already did - the caller's existing error handling is unchanged, only the trigger condition and error message are.
- **Sort options narrowed to a known-safe set**: only `id`, `total`, `status`, and `created_at` are now accepted as sort keys (matching the columns already selected by the query), and only `ASC`/`DESC` as directions. Any other value that previously "worked" by accident (e.g. an expression, a second column tacked onto `direction`) is now rejected. This is the intended effect of the fix, not incidental.
- **Direction is case-normalized**: `direction` is now uppercased before comparison/use, so lowercase input like `asc` is accepted where the original relied on the caller (or MySQL's own leniency) to supply usable casing.
- Sink contract otherwise preserved: `db.execute` is still called with the same `sql`/`[accountId]` shape, `rows` is still returned unchanged, and `fields` is still discarded.
