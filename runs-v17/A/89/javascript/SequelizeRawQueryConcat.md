## Verdict

Confirmed SQL injection via string concatenation of unsanitized request parameters into a raw SQL query.

## Source

The `startDate` and `endDate` query parameters are concatenated directly into the SQL string on lines 12-17 without parameterization or escaping. An attacker can inject SQL metacharacters or additional SQL statements by crafting URLs like `?startDate=2024-01-01' OR '1'='1&endDate=2024-01-31`.

## Fix

### File: SequelizeRawQueryConcat.js

```javascript
const { QueryTypes } = require('sequelize');
const sequelize = require('../db/sequelize');

// GET /reports/orders?startDate=2024-01-01&endDate=2024-01-31
async function getOrderTotalsReport(req, res) {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: 'startDate and endDate are required' });
  }

  const sql =
    'SELECT customer_id, SUM(total_cents) AS total_cents ' +
    'FROM orders ' +
    'WHERE order_date BETWEEN :startDate AND :endDate ' +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  const rows = await sequelize.query(sql, { 
    replacements: { startDate, endDate },
    type: QueryTypes.SELECT 
  });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The fix replaces string concatenation with Sequelize's parameterized query support using the `replacements` option. Named placeholders (`:startDate`, `:endDate`) are substituted with values from the `replacements` object, causing the database driver to treat them as literal values rather than SQL code. This prevents SQL injection regardless of the input content.
