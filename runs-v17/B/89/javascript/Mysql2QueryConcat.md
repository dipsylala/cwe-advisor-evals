## Verdict

Exploitable. User input from `req.params.userId` flows directly into the SQL query string via template literal concatenation, allowing an attacker to inject arbitrary SQL.

## Source

`req.params.userId` (line 15) - extracted from the request URL parameter and used unsanitized.

## Fix

### File: Mysql2QueryConcat.js

```javascript
const express = require('express');
const mysql = require('mysql2');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Returns the order history for a given customer.
router.get('/api/users/:userId/orders', (req, res) => {
  const { userId } = req.params;

  const sql = `SELECT id, item, quantity, total_cents, created_at
               FROM orders
               WHERE user_id = ?
               ORDER BY created_at DESC`;

  // Fixed: Use parameterized query with execute() instead of concatenation
  pool.execute(sql, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to load orders' });
    }
    res.json({ orders: rows });
  });
});

module.exports = router;
```

## Explanation

The vulnerability arises from concatenating the untrusted `userId` parameter directly into the SQL string on line 19 of the original code. An attacker can inject SQL by passing a malicious userId such as `1 OR 1=1`, causing the query to return all orders instead of just the user's. The fix replaces the template literal concatenation with a parameterized query using `mysql2`'s `execute()` method. The placeholder `?` on line 20 marks where the value goes, and the array `[userId]` on line 24 provides the value separately. With `mysql2.execute()`, the database driver sends the SQL structure and the parameter value to the server independently, preventing the server from interpreting user input as query structure. This eliminates the injection vector while preserving the application's functionality.

## Behaviour changes

None. The `execute()` method accepts the same callback signature as `query()` (error and rows), so the response handling and application logic remain unchanged. The only difference is that the parameter is now treated as data rather than part of the query string, which is the intended security improvement.
