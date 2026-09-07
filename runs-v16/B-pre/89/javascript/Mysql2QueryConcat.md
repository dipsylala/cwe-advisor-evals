## Verdict

exploitable

## Source

User-supplied `userId` parameter from the HTTP route handler (`req.params.userId`), line 15.

## Fix

**Vulnerable code:**
```javascript
const { userId } = req.params;

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
const { userId } = req.params;

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

The vulnerability occurs because `userId` is directly interpolated into the SQL query using a template literal, allowing an attacker to inject arbitrary SQL code by manipulating the route parameter. The fix replaces string concatenation with a parameterized query using `?` placeholders and the `.execute()` method. The `.execute()` method sends values to the MySQL server as separate parameters, ensuring the database driver treats the value strictly as data rather than as executable SQL code. This eliminates the injection vector regardless of the input content. The change from `.query()` to `.execute()` is essential: while both accept the `?` syntax, only `.execute()` performs true server-side prepared-statement binding; `.query()` still interpolates client-side through the library's own escaping, which is not a substitute for parameterization.

## Behaviour changes

None. The `.execute()` method on `mysql2` pools accepts the same callback signature as `.query()`, returns rows in the same format, and preserves error handling behaviour. The only change is the mechanism by which values reach the database: instead of being embedded in the query string, they are sent as separate parameters, which is transparent to the application logic.
