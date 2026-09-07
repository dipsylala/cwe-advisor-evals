## Verdict

Confirmed SQL injection in parameterized query sink. The `ids` parameter flows directly into the SQL string via template literal concatenation without parameterization.

## Source

User-supplied `ids` array passed to `getOrdersByIds()` function. The caller provides external data that should be treated as untrusted.

## Fix

Replace string concatenation with parameterized query using `pg` library's `$1`, `$2`, etc. placeholders. Build one placeholder per id value since arrays do not expand automatically in parameterized queries.

```javascript
async function getOrdersByIds(pool, ids) {
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
  const result = await pool.query(`SELECT * FROM orders WHERE id IN (${placeholders})`, ids);
  return result.rows;
}
```

## Explanation

The original code concatenates the joined `ids` directly into a template literal, treating user input as SQL structure. An attacker can inject SQL operators: `ids = ['1', ') OR (1=1'] → WHERE id IN (1) OR (1=1)`.

The fix:
- Builds a placeholder string (`$1,$2,$3,...`) with one placeholder per id
- Passes the `ids` array as a separate parameter to `pool.query()`
- The `pg` driver treats array elements as data values and safely escapes them
- The query structure is fixed; only the values are dynamic

This is the primary defence for SQL injection in Node.js. The `pg` library does not support binding an array to a single placeholder for expansion into an IN list, so multiple placeholders must be generated.

## Behaviour changes

Output format and result set are identical. Application logic is unchanged. Query execution is secure against SQL injection attempts, and performance is equivalent to the vulnerable version.
