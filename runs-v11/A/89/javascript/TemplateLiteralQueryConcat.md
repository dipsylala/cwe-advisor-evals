## Verdict

SQL injection vulnerability confirmed. User-supplied input from `req.query.code` is directly interpolated into an SQL query string on line 16 via template literal, then executed on line 19 without any parameterization or escaping. An attacker can inject arbitrary SQL by supplying a tracking code containing SQL metacharacters.

## Source

```javascript
const trackingCode = req.query.code;
const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;
pool.query(sql, (err, rows) => {
```

The template literal concatenates untrusted user input directly into the SQL string.

## Fix

Replace the string concatenation with a parameterized query using placeholders:

```javascript
const trackingCode = req.query.code;
const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';
pool.query(sql, [trackingCode], (err, rows) => {
```

Pass user input as parameters in an array to `pool.query()` as the second argument. The mysql2 library will handle escaping and binding the parameter safely.

## Explanation

Template literal string interpolation embeds user input directly into the SQL statement, allowing attackers to inject SQL commands. For example, a tracking code like `' OR '1'='1` would modify the WHERE clause logic.

Parameterized queries (prepared statements) separate the SQL statement structure from user data. The database driver handles proper escaping and treats the parameter as a literal value, not executable SQL code. This is the standard defense against SQL injection in Node.js with the mysql2 library.
