## Verdict

Exploitable. The SQL query on line 23 receives untrusted user input that was directly interpolated into the SQL string via template literal on line 19, without parameterization. An attacker can inject SQL operators and logic (e.g., `userId = "1 OR 1=1"`) to manipulate the query's WHERE clause and retrieve all rows in the table.

## Source

`req.params.userId` at line 15. The `userId` path parameter from the HTTP request is extracted and used directly in SQL query construction.

## Fix

**Vulnerable code (line 17-23):**
```javascript
const sql = `SELECT id, item, quantity, total_cents, created_at
             FROM orders
             WHERE user_id = ${userId}
             ORDER BY created_at DESC`;

pool.query(sql, (err, rows) => {
  if (err) {
    return res.status(500).json({ error: 'Failed to load orders' });
  }
  res.json({ orders: rows });
});
```

**Fixed code:**
```javascript
const sql = `SELECT id, item, quantity, total_cents, created_at
             FROM orders
             WHERE user_id = ?
             ORDER BY created_at DESC`;

pool.execute(sql, [userId], (err, rows) => {
  if (err) {
    return res.status(500).json({ error: 'Failed to load orders' });
  }
  res.json({ orders: rows });
});
```

## Explanation

Replace the template literal with a parameterized query. The placeholder `?` marks where the parameter belongs in the SQL string, and the parameter value `userId` is passed separately in an array as the second argument to `execute()`. This ensures the database driver treats the value as data, not as executable SQL code. The `mysql2` library's `execute()` method sends the parameter separately to the server as a true prepared statement, providing stronger protection than `query()`, which interpolates parameters client-side. The injection payload `1 OR 1=1` would now be treated as a string literal to match against `user_id`, not as SQL operators, and would fail to match any rows and return no results instead of bypassing the WHERE clause.

## Behaviour changes

Changed `pool.query()` to `pool.execute()`. This shifts parameter binding from client-side interpolation (in `query()`) to server-side prepared statements (in `execute()`), which aligns with the safety guidance. The behaviour is functionally identical when given valid input: both methods return results in the callback's `rows` parameter. The callback signature and error handling are unchanged. The prepared-statement approach is transparent to the calling code and does not alter the application's functionality.
