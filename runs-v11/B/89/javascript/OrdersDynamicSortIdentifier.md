## Verdict

Exploitable. User-controlled query parameters `sort` and `dir` from `req.query` flow directly into SQL query construction via string concatenation (template literals) in the `ORDER BY` clause without validation.

## Source

Untrusted query parameters in orderController.js:
- Line 7: `const sortColumn = req.query.sort || 'created_at'`
- Line 8: `const direction = req.query.dir || 'DESC'`

These parameters are passed to `findOrders()` at line 10.

## Fix

**Vulnerable code (orderRepository.js, lines 3-12):**

```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,  // SQL injection: untrusted input concatenated into query structure
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

**Fixed code (orderRepository.js, lines 3-20):**

```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  // Allowlist of safe column names
  const allowedColumns = {
    'id': 'id',
    'total_cents': 'total_cents',
    'status': 'status',
    'created_at': 'created_at'
  };

  // Allowlist of safe sort directions
  const allowedDirections = {
    'ASC': 'ASC',
    'DESC': 'DESC'
  };

  // Validate against allowlist; use canonical value from map, never the original input
  const safeColumn = allowedColumns[sortColumn];
  const safeDirection = allowedDirections[direction];

  // Reject if either parameter is not in allowlist
  if (!safeColumn || !safeDirection) {
    throw new Error('Invalid sort column or direction');
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${safeColumn} ${safeDirection}`,  // Uses allowlist values, not user input
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

## Explanation

Column names and `ORDER BY` direction cannot be parameterized in SQL—they are part of query structure, not data values. The fix applies strict allowlist validation: both `sortColumn` and `direction` are checked against a server-controlled map of permitted values. The canonical value from the allowlist is used in the query, never the original user input. This prevents an attacker from injecting SQL commands through these parameters; any unrecognized value is rejected and throws an error. The `accountId` parameter remains properly parameterized with `?` as before.

## Behaviour changes

The function now throws an `Error` if `sortColumn` or `direction` do not match the allowlist. Callers must handle this exception rather than silently falling through to query execution. This is an intentional defensive change—rejecting unknown sort parameters is safer than attempting to sanitize them. Callers should wrap the invocation in a try/catch and respond with a 400 Bad Request error on validation failure.
