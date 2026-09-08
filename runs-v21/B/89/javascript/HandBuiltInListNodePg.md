## Verdict

Exploitable. The `ids` parameter flows unsanitized through string concatenation into the SQL query sink via template literal interpolation, permitting SQL injection at the `IN` clause.

## Source

The `ids` parameter passed to `getOrdersByIds()` at line 1 of orders.js. Untrusted input reaches the SQL query without parameterization.

## Fix

### File: orders.js

```javascript
async function getOrdersByIds(pool, ids) {
  const result = await pool.query(
    'SELECT * FROM orders WHERE id = ANY($1::int[])',
    [ids]
  );
  return result.rows;
}

module.exports = { getOrdersByIds };
```

## Explanation

The fix replaces string concatenation (`${inClause}`) with a parameterized query using pg's native `$1` placeholder syntax and PostgreSQL's `ANY()` operator to handle array expansion. The `ids` array is now passed as a separate parameter to `pool.query()`, ensuring the database driver treats it as data values rather than SQL syntax. The type cast `::int[]` explicitly declares the parameter as an integer array, matching the expected type for the `id` column. This eliminates the injection vector while preserving the original query semantics: `WHERE id = ANY($1::int[])` functionally matches `WHERE id IN (...)` for the input array.

## Behaviour changes

The function now binds parameter values at the driver level rather than interpolating them client-side. The `ANY($1::int[])` pattern replaces `IN (${inClause})` with the same logical outcome—checking membership in a list of IDs—but through parameterization. No return value or contract changes occur; `result.rows` is returned unchanged. Input validation now occurs at the database driver boundary rather than through string manipulation, which is safer and requires no downstream validation of the ids format.
