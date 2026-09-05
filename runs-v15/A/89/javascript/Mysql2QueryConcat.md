## Verdict
SQL injection vulnerability confirmed. Line 19 constructs an SQL query using template string interpolation with user-supplied input (`userId` from `req.params`), allowing an attacker to inject arbitrary SQL commands. Line 23 executes this unsanitized query without parameterization.

## Source
```javascript
const { userId } = req.params;

const sql = `SELECT id, item, quantity, total_cents, created_at
             FROM orders
             WHERE user_id = ${userId}
             ORDER BY created_at DESC`;

pool.query(sql, (err, rows) => {
  // ...
});
```

The user-controlled `userId` parameter is concatenated directly into the SQL string, enabling injection attacks such as `userId=1 OR 1=1` or `userId=1; DROP TABLE orders;`.

## Fix
Replace template string interpolation with parameterized queries using placeholder syntax. Pass user input as a separate parameter array to the `query()` method:

```javascript
router.get('/api/users/:userId/orders', (req, res) => {
  const { userId } = req.params;

  const sql = `SELECT id, item, quantity, total_cents, created_at
               FROM orders
               WHERE user_id = ?
               ORDER BY created_at DESC`;

  pool.query(sql, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to load orders' });
    }
    res.json({ orders: rows });
  });
});
```

## Explanation
Parameterized queries (prepared statements) separate SQL command logic from data. The `?` placeholder marks where data belongs, and the mysql2 driver handles escaping and type conversion internally. This ensures user input cannot alter the query structure. The parameter array `[userId]` supplies values for each placeholder in order, preventing the string interpolation attack vector entirely.
