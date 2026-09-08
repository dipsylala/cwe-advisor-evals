## Verdict

Exploitable. Untrusted user input from `req.query` parameters `startDate` and `endDate` flows directly into SQL query construction via string concatenation, allowing SQL injection at the `sequelize.query()` sink.

## Source

`req.query.startDate` and `req.query.endDate` - user-supplied GET parameters from the HTTP request, treated as untrusted data.

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
    'WHERE order_date BETWEEN $1 AND $2 ' +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  const rows = await sequelize.query(sql, { type: QueryTypes.SELECT, bind: [startDate, endDate] });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
```

## Explanation

The original code builds SQL by concatenating untrusted `startDate` and `endDate` parameters directly into the query string (lines 12-17 of the original). An attacker can inject SQL by providing values like `2024-01-01' OR '1'='1`, which would break out of the string literal and inject arbitrary WHERE clause logic. The fix replaces string concatenation with Sequelize's parameterized query API using positional placeholders `$1` and `$2` combined with the `bind: [startDate, endDate]` option. This ensures the database driver treats the parameter values as data, not executable SQL syntax, eliminating the injection vector.

## Behaviour changes

None. The query executes identically to the original - it returns the same result set with the same columns and types. The `bind` parameter is a Sequelize mechanism for secure parameter passing that does not alter the query's semantics or results. The HTTP response format and controller logic remain unchanged.
