## Verdict

exploitable

## Source

`req.params.userId` in the `GET /api/users/:userId/orders` handler (Express route parameter, fully attacker-controlled).

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

`userId` flowed from the route parameter straight into a template literal that built the SQL text, so a value like `1 OR 1=1` or a UNION-based payload became part of the query's structure rather than a bound value, giving an attacker read access to other customers' order data. The fix replaces the template-literal interpolation with a `?` placeholder and moves the call from `pool.query()` to `pool.execute()`: with `mysql2`, `query()` only interpolates bound values client-side through the driver's own escaping, while `execute()` sends the SQL and the value separately as a true prepared statement, so `userId` is always treated as data and can no longer alter the query's structure regardless of its content.

## Behaviour changes

none - the query still selects the same columns, filters on the same `user_id` comparison, orders the results the same way, and the success/error response shapes (`{ orders: rows }` / 500 with `{ error: 'Failed to load orders' }`) are unchanged. MySQL performs the same string-to-integer coercion when comparing the bound `userId` value against `user_id` that it performed on the previously interpolated literal, so non-injection inputs behave identically.

**Verification:** the fixed file was copied to a scratch location and checked with `node --check`, which reported no syntax errors. `pool.execute()` is a standard `mysql2` `Pool` method (documented alongside `pool.query()` for prepared-statement execution) and was not otherwise modified from its normal calling convention, so no new unverified names were introduced.
