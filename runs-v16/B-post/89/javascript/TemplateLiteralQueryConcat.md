## Verdict

Real vulnerability - SQL Injection via template literal concatenation. Untrusted user input (`req.query.code`) is directly interpolated into a SQL query string, allowing attackers to inject arbitrary SQL commands.

## Source

**File:** `evals/cases/89/javascript/TemplateLiteralQueryConcat/TemplateLiteralQueryConcat.js`
**Line:** 14-19

**Source:** Line 14 - `const trackingCode = req.query.code;` (untrusted HTTP query parameter)

**Data flow:**
1. Line 14: User input received from query string
2. Line 16: Value interpolated directly into SQL template literal: `` `SELECT ... WHERE tracking_code = '${trackingCode}'` ``
3. Line 19: Concatenated SQL string passed to `pool.query()`

**Attack scenario:** An attacker could submit `?code=' OR '1'='1` to transform the query to `SELECT id, status, eta FROM orders WHERE tracking_code = '' OR '1'='1'`, returning all orders regardless of tracking code.

## Fix

**Vulnerable code (lines 13-28):**
```javascript
router.get('/orders/track', (req, res) => {
  const trackingCode = req.query.code;

  const sql = `SELECT id, status, eta FROM orders WHERE tracking_code = '${trackingCode}'`;

  // SAST FINDING: CWE-89 reported here
  pool.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'lookup failed' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'order not found' });
    }
    res.json(rows[0]);
  });
});
```

**Fixed code:**
```javascript
router.get('/orders/track', (req, res) => {
  const trackingCode = req.query.code;

  const sql = 'SELECT id, status, eta FROM orders WHERE tracking_code = ?';

  pool.execute(sql, [trackingCode], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'lookup failed' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'order not found' });
    }
    res.json(rows[0]);
  });
});
```

**Changes:**
1. Line 16: Replace template literal with static SQL string using `?` placeholder
2. Line 19: Change `pool.query()` to `pool.execute()` and pass `trackingCode` as a separate parameter in an array `[trackingCode]`

## Explanation

The fix replaces string concatenation with a parameterized query using `pool.execute()`. The `execute()` method in mysql2 prepares the statement server-side and transmits parameter values separately from the query structure, ensuring untrusted input is always treated as data, never as executable SQL syntax.

The template literal (`` ` ... ${var} ` ``) directly interpolates the value into the query string, giving an attacker direct control over SQL syntax. Parameterized queries with `?` placeholders enforce a hard boundary between query logic and data: the database driver parses the query structure first, then binds the provided values into the appropriate positions as data only.

The callback signature and error handling remain unchanged - the fix is surgical and preserves the original async control flow.

## Behaviour changes

- **Query execution:** Now uses server-side prepared statements instead of client-side string interpolation, eliminating template-literal injection
- **Performance:** Marginal improvement - prepared statements can be cached and reused by the database
- **Parameter passing:** Values now transmitted as separate parameters in an array rather than embedded in the SQL string
- **Error handling:** Unchanged - callback still receives errors in the same format
- **Output:** Unchanged - rows are returned and processed identically
