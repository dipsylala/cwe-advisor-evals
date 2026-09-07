## Verdict

TRUE_POSITIVE: SQL Injection vulnerability confirmed. Untrusted user input (`startDate` and `endDate` from `req.query`) is concatenated directly into the SQL query string, allowing attackers to inject arbitrary SQL commands. This flows to the Sequelize query sink at line 20 where `sequelize.query()` executes the malicious SQL.

## Source

User input from HTTP query parameters at line 6:
```javascript
const { startDate, endDate } = req.query;
```

These values are untrusted and attacker-controlled via URL query string (e.g., `GET /reports/orders?startDate=2024-01-01' OR '1'='1&endDate=2024-01-31`).

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
    'WHERE order_date BETWEEN $startDate AND $endDate ' +
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

The fix replaces string concatenation with Sequelize's parameterized query mechanism using the `bind` option. The SQL query now uses named parameter placeholders (`$startDate`, `$endDate`) instead of embedding the values directly. The `bind` object provides these values as separate parameters to Sequelize, which sends them to the database driver as values, not as executable SQL code.

This eliminates the SQL injection vulnerability because:
1. The query structure (SQL syntax) is fixed and known at query time
2. User input in the `bind` object is always treated as literal data values
3. The database driver applies appropriate escaping and type handling for the specific column types
4. Malicious SQL syntax in the input (e.g., `' OR '1'='1`) is treated as a string value, not as SQL structure

The fix uses Sequelize's `query(sql, { bind })` API which uses real driver-level parameterization (via the underlying adapter like `mysql2`, `pg`, etc.), not client-side string escaping. This is the primary defence recommended in CWE-89 guidance.

## Behaviour changes

None. The endpoint accepts the same parameters, executes the same logical query (filtered by `startDate` and `endDate` in the same way), and returns the same result structure. The only difference is that the database receives a parameterized query instead of a concatenated string, which is an implementation detail transparent to callers.
