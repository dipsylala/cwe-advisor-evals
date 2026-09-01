## Verdict
**SQL Injection via unvalidated sort column and direction parameters**

The query on line 8 directly interpolates user-controlled `sortColumn` and `direction` parameters into the SQL string. An attacker can inject arbitrary SQL by supplying a malicious value for either parameter, for example `sortColumn = "id; DELETE FROM orders; --"`.

## Source
Line 8 in orderRepository.js:
```javascript
`ORDER BY ${sortColumn} ${direction}`
```

The `sortColumn` and `direction` parameters flow directly from the function arguments (line 3) into the SQL query without validation or sanitization. Parameter binding on line 11 (`[accountId]`) only protects the WHERE clause value, not the ORDER BY clause.

## Fix
Implement an allowlist for both `sortColumn` and `direction`:

```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  // Whitelist valid columns to prevent injection
  const validColumns = ['id', 'total_cents', 'status', 'created_at'];
  const validDirections = ['ASC', 'DESC'];
  
  if (!validColumns.includes(sortColumn) || !validDirections.includes(direction.toUpperCase())) {
    throw new Error('Invalid sort parameters');
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
```

## Explanation
Parameter binding (the `?` placeholder on line 11) prevents SQL injection for VALUES only, not for identifiers or keywords. Column names and SQL keywords like ASC/DESC cannot be parameterized—they must be validated against a whitelist of acceptable values before being interpolated into the query string. The fix checks that `sortColumn` is one of the columns the query actually selects and that `direction` is either 'ASC' or 'DESC' (case-insensitive), rejecting any other input.
