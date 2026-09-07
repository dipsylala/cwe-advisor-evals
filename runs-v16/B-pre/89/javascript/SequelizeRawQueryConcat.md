## Verdict

Exploitable. User-controlled `startDate` and `endDate` query parameters are concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL logic.

## Source

Attacker-controlled query parameters: `startDate` and `endDate` from `req.query` (lines 6, 15).

Example malicious input: `startDate="2024-01-01' OR '1'='1"` would escape the string context and alter query logic.

## Fix

**Vulnerable code (lines 12–20):**

```javascript
let sql =
    'SELECT customer_id, SUM(total_cents) AS total_cents ' +
    'FROM orders ' +
    "WHERE order_date BETWEEN '" + startDate + "' AND '" + endDate + "' " +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

const rows = await sequelize.query(sql, { type: QueryTypes.SELECT });
```

**Fixed code:**

```javascript
const rows = await sequelize.query(
  'SELECT customer_id, SUM(total_cents) AS total_cents ' +
  'FROM orders ' +
  'WHERE order_date BETWEEN ? AND ? ' +
  'GROUP BY customer_id ' +
  'ORDER BY total_cents DESC',
  { type: QueryTypes.SELECT, bind: [startDate, endDate] }
);
```

The fix uses Sequelize's `bind` option for parameterized query execution. The `?` placeholders are replaced by the driver with properly escaped values at query execution time, preventing SQL injection. The `bind` array passes the untrusted values as parameters rather than concatenating them into the query string.

## Explanation

String concatenation of user input into SQL queries allows attackers to inject SQL syntax and manipulate query logic. Parameterized queries (prepared statements) separate query structure from data values: the SQL string contains only placeholders (`?`), and the actual user values are sent separately to the database driver for proper escaping and type handling. Sequelize's `bind` option uses the underlying database driver's native parameterization, which is the primary defence against SQL injection. The alternative `replacements` option performs client-side escaping, which is weaker and not recommended in the guidance.

## Behaviour changes

None. The query logic, return value, error handling, and result set remain identical. Only the parameter binding mechanism changes from string concatenation to driver-level parameterization.
