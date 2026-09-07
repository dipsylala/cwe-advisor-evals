## Verdict

Not exploitable

## Source

`request.getParameter("name")` at Case14A.java:15 returns untrusted user input passed to `Case14B.handleSink()`.

## Fix

No fix required. The code already implements the correct defense against SQL injection using parameterized queries.

## Explanation

The reported sink at Case14B.java:29 (`sqlStatement.executeQuery()`) is protected by correct use of `PreparedStatement`. The SQL query string at line 25 is built statically as `"select * from users where name=?"` with no user input concatenation. The untrusted data parameter is bound safely at line 26 using `setString(1, data)`, which ensures it is always treated as data, never as executable SQL code. This parameterized query pattern is the primary defense against SQL injection as recommended in CWE-89 guidance. The attack chain is broken because the query structure is fixed before the untrusted data reaches the execute call.

## Behaviour changes

None. The code requires no modifications.
