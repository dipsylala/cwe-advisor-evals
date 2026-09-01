## Verdict

Exploitable. The `sortColumn` and `direction` parameters are untrusted user input directly interpolated into the SQL query via template literal without validation or parameterization, allowing SQL injection attacks.

## Source

User input from HTTP query parameters (`req.query.sort` and `req.query.dir`) in orderController.js lines 7-8, passed unsanitized to findOrders() in orderRepository.js.

## Fix

Replace the vulnerable code that directly interpolates sortColumn and direction with validated values from an allowlist:

**Vulnerable code (orderRepository.js):**
```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,  // Direct interpolation - vulnerable
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

**Fixed code:**
```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  // Allowlist permitted sort columns - maps to server-controlled values
  const allowedColumns = {
    'id': 'id',
    'total_cents': 'total_cents',
    'status': 'status',
    'created_at': 'created_at',
  };

  // Allowlist permitted sort directions - normalize to uppercase
  const allowedDirections = {
    'ASC': 'ASC',
    'DESC': 'DESC',
    'asc': 'ASC',
    'desc': 'DESC',
  };

  // Validate and extract values from allowlist, not from user input
  const validatedColumn = allowedColumns[sortColumn];
  const validatedDirection = allowedDirections[direction];

  if (!validatedColumn) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }

  if (!validatedDirection) {
    throw new Error(`Invalid sort direction: ${direction}`);
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${validatedColumn} ${validatedDirection}`,  // Use allowlist-validated values
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

## Explanation

The fix implements strict allowlist validation for dynamic SQL identifiers (column names and sort directions) that cannot be parameterized. Instead of using the untrusted input directly, the code treats the user input as a key into a server-controlled map of permitted values. Only values that exist in the allowlist are used in the SQL query; any other input triggers an error. This prevents attackers from injecting SQL through these parameters. The allowlist approach is mandated by the SQL Injection guidance for dynamic identifiers: parameterized queries protect data values but not query structure, so column names and sort directions must be validated against a fixed set of permitted identifiers.

## Behaviour changes

None. The fix preserves the original query logic: it still allows sorting by any of the four allowed columns in either ASC or DESC direction (case-insensitive for direction). The error-throwing behavior on invalid input is appropriate for this context, as invalid sort parameters represent either attacker input or application bugs that should be surfaced rather than silently ignored. The function's return contract is unchanged.
