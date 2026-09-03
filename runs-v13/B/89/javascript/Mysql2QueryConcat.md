## Verdict

Exploitable. User input from `req.params.userId` flows unsanitized through a template literal directly into a SQL query string, then passed to `pool.query()` without parameterization. An attacker can inject SQL operators and logic (e.g., `1 OR 1=1`, `1 UNION SELECT ...`) to bypass authorization or extract arbitrary data.

## Source

`req.params.userId` at line 15 - untrusted HTTP request parameter from the URL path.

## Fix

**Vulnerable code:**
```javascript
const sql = `SELECT id, item, quantity, total_cents, created_at
             FROM orders
             WHERE user_id = ${userId}
             ORDER BY created_at DESC`;

pool.query(sql, (err, rows) => {
```

**Fixed code:**
```javascript
const sql = `SELECT id, item, quantity, total_cents, created_at
             FROM orders
             WHERE user_id = ?
             ORDER BY created_at DESC`;

pool.execute(sql, [userId], (err, rows) => {
```

## Explanation

The fix replaces the template literal interpolation with a parameterized query using the `?` placeholder. The user input `userId` is now passed as a separate element in an array to `pool.execute()` instead of being concatenated into the query string. With `mysql2`, `execute()` sends the parameter values separately from the query structure (server-side preparation), ensuring they are always treated as data, never as executable SQL. This closes the SQL injection vector - an attacker passing `1 OR 1=1` or any SQL operator will have it treated as a literal string value to match against the `user_id` column, not as query logic.

## Behaviour changes

- Changed from `pool.query()` to `pool.execute()`: `mysql2` distinguishes these two methods. `query()` interpolates parameters client-side (still vulnerable even with placeholders), while `execute()` sends them server-side, achieving true parameterization. Both have identical method signatures and return the same result shape, so the swap has no other impact on caller code or error handling.
