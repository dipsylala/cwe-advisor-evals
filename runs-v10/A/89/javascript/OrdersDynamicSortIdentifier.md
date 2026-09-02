## Verdict
SQL injection vulnerability confirmed. The `sortColumn` and `direction` parameters are directly interpolated into the SQL query without validation or escaping.

## Source
Line 8 in the ORDER BY clause:
```javascript
`ORDER BY ${sortColumn} ${direction}`
```

The `sortColumn` parameter comes directly from user input through the function argument without sanitization before being embedded in the SQL string passed to `db.execute()` on line 11.

## Fix
Validate both `sortColumn` and `direction` against allowlists before constructing the query:

```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  const allowedColumns = ['id', 'total_cents', 'status', 'created_at'];
  const allowedDirections = ['ASC', 'DESC'];

  if (!allowedColumns.includes(sortColumn)) {
    throw new Error(`Invalid sort column: ${sortColumn}`);
  }
  if (!allowedDirections.includes(direction.toUpperCase())) {
    throw new Error(`Invalid sort direction: ${direction}`);
  }

  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction.toUpperCase()}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

## Explanation
ORDER BY column identifiers cannot be parameterized with `?` placeholders—they must be part of the query structure. The remediation uses an allowlist to restrict `sortColumn` to only known, safe column names from the select list, and validates that `direction` is one of the valid SQL keywords. This prevents attackers from injecting arbitrary SQL through these parameters while preserving the intended dynamic sorting behavior.
