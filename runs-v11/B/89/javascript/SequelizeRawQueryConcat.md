## Verdict

Confirmed. The finding is exploitable.

## Source

Untrusted query parameters `startDate` and `endDate` from `req.query` (attacker-controlled HTTP request parameters) at lines 6.

## Fix

Replace string concatenation with parameterized query using Sequelize's `bind` parameter:

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
    'WHERE order_date BETWEEN $1 AND $2 ' +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  const rows = await sequelize.query(sql, { 
    type: QueryTypes.SELECT,
    bind: [startDate, endDate]
  });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The vulnerability exists at lines 12-17 where the SQL query is constructed by concatenating untrusted `startDate` and `endDate` values directly into the SQL string. An attacker can inject SQL by passing values like `2024-01-01' OR '1'='1` to break out of the string literal and manipulate the query logic.

The fix replaces string concatenation with parameterized query syntax. Sequelize's `query()` method with the `bind` parameter sends the SQL statement structure separately from the parameter values to the database driver, ensuring user input is always treated as data, never as executable SQL syntax. The `$1` and `$2` placeholders mark where parameters are substituted, and the actual values in the `bind` array are passed as separate parameters. This prevents SQL injection regardless of the input content.

## Behaviour changes

No functional behaviour changes. The query returns identical results for valid inputs (properly formatted dates). The fix closes the injection vulnerability while maintaining the same query semantics and output format.
