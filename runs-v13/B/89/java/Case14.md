## Verdict

Not exploitable. The code correctly uses parameterized queries with bound parameters. This is a false positive from the SAST tool.

## Source

Untrusted HTTP request parameter obtained via `request.getParameter("name")` in Case14A.java at line 15, passed to Case14B.handleSink() at line 17.

## Fix

No fix required. The code is already secure.

The vulnerable pattern would be string concatenation into the SQL query:
```java
String query = "select * from users where name='" + data + "'";
sqlStatement = dbConnection.prepareStatement(query);
```

The actual code correctly uses parameterized queries:
```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
```

## Explanation

The code implements the correct primary defense against SQL Injection: parameterized queries with bound parameters. The SQL query string on line 25 is a static literal containing a `?` placeholder. The untrusted input `data` is bound to this placeholder on line 26 using `setString()`, which ensures it is treated as a value, not as part of the SQL structure. The database driver separates query logic from data at the protocol level, making injection impossible. The untrusted input never reaches a position where it can alter query structure.

## Behaviour changes

None. The existing code is secure and requires no modification.
