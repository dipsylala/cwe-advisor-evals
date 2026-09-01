## Verdict

Exploitable. User-supplied query parameter `code` is interpolated directly into a SQL query string via template literal without parameterization, allowing SQL injection at the sink `pool.query()` on line 19.

## Source

`req.query.code` (line 14) - attacker-controlled query parameter flowing directly into the SQL string constructed on line 16.

## Fix

**Vulnerable code:**
```javascript
const trackingCode = req.query.code;

const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

pool.query(sql, (err, rows) => {
  // ...
});
```

**Fixed code:**
```javascript
const trackingCode = req.query.code;

const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

pool.execute(sql, [trackingCode], (err, rows) => {
  // ...
});
```

## Explanation

The fix replaces string concatenation via template literal with parameterized query execution. The SQL string now contains a `?` placeholder instead of interpolating `trackingCode`. The `mysql2` library's `execute()` method sends the SQL structure and parameter values separately to the database, ensuring the parameter is always treated as a literal value, never as executable SQL syntax. This prevents attackers from injecting SQL metacharacters (quotes, semicolons, comments) that would alter query logic. Template literals and string concatenation are replaced with the proper parameterization pattern for `mysql2`.

## Behaviour changes

1. **Method switch from `query()` to `execute()`**: The `mysql2` library provides two methods for query execution. `query()` interpolates values client-side through the library's own escaping, which is not true parameterization; `execute()` prepares the statement server-side and sends parameters separately, providing true parameterized query protection. This method switch is required for the fix to be effective.

2. **Parameter passing**: Parameters now pass as an array in the second argument to `execute()`, `[trackingCode]`, rather than being embedded in the SQL string. The database driver handles binding and escaping.

These changes preserve the original sink contract: `execute()` maintains the same callback-based error handling and result format as `query()`, so the error checking and response generation code remain unchanged.
