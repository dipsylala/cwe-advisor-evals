## Verdict

Exploitable. User-supplied `sortColumn` and `direction` values are concatenated directly into the SQL query via template literal interpolation without validation or parameterization, allowing an attacker to inject arbitrary SQL.

## Source

The `sortColumn` and `direction` parameters of the `findOrders()` function in `orderRepository.js` (line 3), which are caller-supplied values representing untrusted user input such as HTTP query parameters.

## Fix

**Vulnerable code:**
```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,  // SQL injection: values interpolated without validation
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

**Fixed code:**
```javascript
async function findOrders(db, accountId, sortColumn, direction) {
  // Map of permitted sort columns to their SQL identifiers
  const sortColumnMap = {
    'id': 'id',
    'total_cents': 'total_cents',
    'status': 'status',
    'created_at': 'created_at'
  };
  
  // Map of permitted directions to canonical forms
  const directionMap = {
    'asc': 'ASC',
    'desc': 'DESC',
    'ASC': 'ASC',
    'DESC': 'DESC'
  };
  
  // Validate and extract canonical values from allowlists
  const validatedColumn = sortColumnMap[sortColumn];
  const validatedDirection = directionMap[direction];
  
  if (!validatedColumn || !validatedDirection) {
    throw new Error('Invalid sort parameters');
  }
  
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${validatedColumn} ${validatedDirection}`,  // Safe: values from allowlist, never user input
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}
```

## Explanation

SQL injection is eliminated by treating `sortColumn` and `direction` as keys into server-controlled allowlist maps rather than as user input to validate and pass through. The values that reach the query construction are always the allowlist's canonical values, never the caller's original input. This prevents injection because an attacker cannot inject SQL through a fixed set of predefined strings. The allowlist approach is necessary here because column names and SQL keywords like `ORDER BY` directions cannot be parameterized in any SQL dialect—parameterization only works for data values, not for query structure. The validation at the boundary rejects both obvious attacks (`'; DROP TABLE orders; --`) and edge cases (case variation, null inputs) in a single checkpoint. The accountId parameter remains properly bound and is never at risk.

## Behaviour changes

None. The fix preserves the original function contract: it returns the same row array, accepts the same parameters, and throws an error only when invalid inputs would have produced a malformed or dangerous query. A user request with an unsupported sort column now throws rather than silently falling through to undefined behavior, which is correct practice for API validation.
