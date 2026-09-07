## Verdict

CONFIRMED: SQL injection vulnerability via string concatenation in query construction.

## Source

Untrusted user input from `req.query.startDate` and `req.query.endDate` (line 6) flows directly into SQL query string via concatenation on lines 15-16 without parameterization.

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
    bind: { startDate, endDate }
  });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The vulnerability was eliminated by replacing string concatenation with Sequelize's parameterized query mechanism. The fix converts the SQL string to use named parameter placeholders (`:startDate`, `:endDate`) and passes the untrusted values through the `bind` option to `sequelize.query()`. This ensures that the database driver treats user input as data values, not as executable SQL code, preventing SQL injection. The `bind` option uses real driver parameterization (unlike `replacements`, which performs client-side escaping). All other behavior is preserved: the query returns the same result set, error handling remains unchanged, and the SELECT type specification is maintained.

## Behaviour changes

None. The parameterized query produces identical result sets with the same row structure and column names. Error handling, return type, and response format are unchanged.
