## Verdict

CONFIRMED: SQL injection vulnerability via string concatenation of unsanitized query parameters into a Sequelize raw query.

## Source

User-supplied query parameters (`startDate` and `endDate` from `req.query`) are concatenated directly into the SQL query string at line 15 without parameterization or escaping.

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

  let sql =
    'SELECT customer_id, SUM(total_cents) AS total_cents ' +
    'FROM orders ' +
    'WHERE order_date BETWEEN :startDate AND :endDate ' +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  const rows = await sequelize.query(sql, { 
    type: QueryTypes.SELECT,
    replacements: { startDate, endDate }
  });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The vulnerability occurs because user input from `req.query` is concatenated directly into the SQL string, allowing attackers to inject arbitrary SQL. For example, an attacker could supply `startDate=2024-01-01' OR '1'='1` to bypass the date filter or extract unauthorized data.

The fix uses Sequelize's parameterized query feature via the `replacements` option. The query string uses named placeholders (`:startDate` and `:endDate`), and the `replacements` object maps these placeholders to sanitized parameter values. Sequelize handles proper escaping internally, preventing SQL injection by separating the query structure from the data.

