## Verdict

exploitable

## Source

The `ids` parameter passed to `getOrdersByIds()`, line 1.

## Sink

`pool.query()` call with a template literal that concatenates the `inClause` string directly into the SQL query, line 5.

## Fix

**Vulnerable code:**
```javascript
async function getOrdersByIds(pool, ids) {
  const inClause = ids.join(',');

  // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
  const result = await pool.query(`SELECT * FROM orders WHERE id IN (${inClause})`);
  return result.rows;
}
```

**Fixed code:**
```javascript
async function getOrdersByIds(pool, ids) {
  // Build parameterized placeholders for pg: $1, $2, $3, etc.
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');

  // FIXED: Use parameterized query with separate parameter binding
  const result = await pool.query(
    `SELECT * FROM orders WHERE id IN (${placeholders})`,
    ids
  );
  return result.rows;
}
```

## Explanation

The original code builds the `IN` clause by concatenating user-supplied IDs directly into the template literal, allowing attackers to inject arbitrary SQL (e.g., passing `1), NULL--(` to break the query syntax). The fixed code constructs the parameterized query dynamically by building placeholders (`$1`, `$2`, etc.) for each element in the `ids` array, then passes the array separately to `pool.query()`. The `pg` library treats this as a parameterized query where values are bound server-side and always interpreted as data, not SQL structure, closing the injection vector.

## Behaviour changes

none
