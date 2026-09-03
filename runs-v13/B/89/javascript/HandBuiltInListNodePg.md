## Verdict

Exploitable

## Source

`ids` parameter (attacker-controlled array of database ID values)

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
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
  const result = await pool.query(
    `SELECT * FROM orders WHERE id IN (${placeholders})`,
    ids
  );
  return result.rows;
}
```

## Explanation

The original code concatenates user-supplied id values directly into the SQL query string via a template literal, allowing SQL injection. The fix replaces the unsafe string interpolation with parameterized query binding: placeholders like `$1`, `$2` are generated based on the array length and interpolated into the SQL structure (not the values), while the actual id values are passed separately as the second argument to `pool.query()`. The PostgreSQL driver (`pg` library) treats the values array as untrusted data and handles proper escaping/parameterization, ensuring that even malicious characters in the id values are treated as literal string data and cannot alter query logic.

## Behaviour changes

None. The query structure, return value, and error handling remain identical. The only change is where the values originate—from a separate, parameterized argument rather than from string interpolation.
