## Verdict

Not exploitable. The code uses parameterized queries with PreparedStatement, which prevents SQL injection by treating user input as data, not executable SQL code.

## Source

Case14A.java, line 15: `data = request.getParameter("name");`

Untrusted user input flows from the HTTP request parameter to Case14B.handleSink().

## Fix

No fix needed. The code is already secure.

The vulnerability is prevented by the existing implementation:
- Line 25 creates a PreparedStatement with a `?` placeholder in the SQL query
- Line 26 binds the user input using `setString(1, data)`, which treats it as a data value
- Line 29 executes the prepared statement

This is the correct and safe pattern for preventing SQL injection in JDBC.

## Explanation

The reported vulnerability at line 29 (the `executeQuery()` call) does not represent an exploitable SQL injection because the data flow is protected by parameterized query usage. The SQL query structure is defined with a `?` placeholder on line 25, before any user input is involved. On line 26, the untrusted data is bound to this placeholder using `setString()`, which the JDBC driver handles by treating the input as a literal string value, not as SQL syntax. Even if an attacker submits SQL metacharacters like `' OR '1'='1`, the database driver will escape them appropriately and treat them as literal characters within the string value, not as SQL commands. This is the primary defense mechanism for SQL injection in JDBC, as documented in the CWE-89 Java guidance.

## Behaviour changes

None. The code requires no modifications; the existing implementation already closes the vulnerability through proper use of PreparedStatement with parameter binding.
