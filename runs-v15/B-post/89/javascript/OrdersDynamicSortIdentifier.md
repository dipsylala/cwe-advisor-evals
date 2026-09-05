## Verdict

Exploitable. Untrusted user input from `req.query.sort` and `req.query.dir` flows through `orderController.js` into `orderRepository.js` and is concatenated into the SQL `ORDER BY` clause without validation. An attacker can inject arbitrary SQL by crafting query parameters, bypassing the parameterized query that protects only the `accountId` value.

## Source

`orderController.js`, lines 7–8:
- `const sortColumn = req.query.sort || 'created_at';` — user-supplied query parameter
- `const direction = req.query.dir || 'DESC';` — user-supplied query parameter

These untrusted values are passed to `findOrders()` in `orderRepository.js`.

## Sink

`orderRepository.js`, line 8:
```javascript
`ORDER BY ${sortColumn} ${direction}`,
```

The template literal concatenates untrusted input directly into the SQL string, allowing injection of arbitrary SQL operators and conditions.

## Fix

**Vulnerable code (orderRepository.js):**
```javascript
'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,  // ← SQL injection: sortColumn and direction are untrusted
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

**Fixed code (orderRepository.js):**
```javascript
'use strict';

// Whitelist of allowed sort columns — only those returned by the SELECT
const ALLOWED_SORT_COLUMNS = new Set(['id', 'total_cents', 'status', 'created_at']);

// Whitelist of allowed sort directions
const ALLOWED_DIRECTIONS = new Set(['ASC', 'DESC']);

async function findOrders(db, accountId, sortColumn, direction) {
  // Validate sort column against whitelist; fallback to safe default if invalid
  if (!ALLOWED_SORT_COLUMNS.has(sortColumn)) {
    sortColumn = 'created_at';
  }

  // Validate direction against whitelist (case-insensitive); fallback to safe default if invalid
  const upperDirection = direction.toUpperCase();
  if (!ALLOWED_DIRECTIONS.has(upperDirection)) {
    direction = 'DESC';
  } else {
    direction = upperDirection;
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
```

## Explanation

The fix adds whitelists for both `sortColumn` and `direction`. The sort column is validated against the set of columns actually present in the `SELECT` clause (`id`, `total_cents`, `status`, `created_at`). The direction is validated against the only two valid SQL sort directions (`ASC`, `DESC`), with case-insensitive matching since SQL accepts both cases. If either value does not match the whitelist, it falls back to a safe default (`created_at` for the column, `DESC` for the direction), matching the original application's default behavior. The validated value — never the untrusted input — is then used in the SQL template literal. Parameterized queries cannot bind structural SQL elements like column names and sort direction keywords, so allowlist validation is the correct defence for these positions.

## Behaviour changes

The fix normalizes the direction to uppercase SQL form (`ASC` or `DESC`). If the caller supplies an invalid direction like `'asc'` or `'ascending'`, the original code would have inserted it verbatim into the query and produced a database error, while the fixed code silently falls back to `DESC`. This is an improvement over the original, as it is more robust to case variation and unexpected input without breaking the application. The `accountId` parameter is still passed through the parameterized query interface unchanged. All other contract elements (return type, function signature, error paths for database failures) are identical.

