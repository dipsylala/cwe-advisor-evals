## Verdict

**Exploitable.** Untrusted user input from `req.query.startDate` and `req.query.endDate` is concatenated directly into a SQL query string (lines 12–17) and executed via `sequelize.query()` at line 20 without parameterization. An attacker can inject SQL operators and logic by crafting payloads like `2024-01-01' OR '1'='1` to manipulate query behaviour.

## Source

Lines 6, 12–17, 20 in `SequelizeRawQueryConcat.js`:
- **Source:** `req.query` (HTTP request parameters `startDate` and `endDate`), lines 6
- **Data flow:** Values extracted from query params, concatenated into SQL string via `+` operator (lines 15), passed to `sequelize.query()` as unparameterized SQL
- **Sink:** `sequelize.query(sql, { type: QueryTypes.SELECT })` at line 20

## Fix

**Vulnerable code (lines 12–20):**
```javascript
let sql =
  'SELECT customer_id, SUM(total_cents) AS total_cents ' +
  'FROM orders ' +
  "WHERE order_date BETWEEN '" + startDate + "' AND '" + endDate + "' " +
  'GROUP BY customer_id ' +
  'ORDER BY total_cents DESC';

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
const rows = await sequelize.query(sql, { type: QueryTypes.SELECT });
```

**Fixed code:**
```javascript
let sql =
  'SELECT customer_id, SUM(total_cents) AS total_cents ' +
  'FROM orders ' +
  'WHERE order_date BETWEEN ? AND ? ' +
  'GROUP BY customer_id ' +
  'ORDER BY total_cents DESC';

const rows = await sequelize.query(sql, { 
  type: QueryTypes.SELECT,
  bind: [startDate, endDate]
});
```

## Explanation

The fix replaces string concatenation with parameterized query placeholders (`?`). Instead of embedding user input directly into the SQL string, the values are passed separately via the `bind` option to `sequelize.query()`. This ensures Sequelize treats the values as data, not as executable SQL structure. The driver handles escaping and type coercion at the protocol level, preventing attackers from injecting SQL operators or logic through the date parameters. The `type: QueryTypes.SELECT` option is preserved to enforce read-only behaviour.

## Behaviour changes

- **Query execution:** The SQL query is prepared once with placeholders and executed with bound parameters. No change to the result set or error handling.
- **Return value:** `rows` contains the same result set as before.
- **Performance:** Prepared statement binding is handled by the underlying database driver (mysql2, pg, etc.); Sequelize's `bind` option uses real driver parameters, so performance is identical to or better than string concatenation.
- **Error handling:** Errors on invalid date formats or SQL execution are raised identically; no behavioural change.
