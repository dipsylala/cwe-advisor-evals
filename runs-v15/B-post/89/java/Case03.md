## Verdict

Exploitable - SQL Injection via direct string concatenation

## Source

`request.getParameter("name")` in Case03A.java - HTTP request parameter flows through Case03B, C, D, E without validation or sanitization

## Fix

**Vulnerable code (Case03E.java, lines 20 and 28):**
```java
sqlStatement = dbConnection.createStatement();
// ...
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**
```java
sqlStatement = dbConnection.prepareStatement("select * from users where name = ?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation

The vulnerability occurs because untrusted user input from the HTTP request parameter is directly concatenated into the SQL query string. This allows an attacker to inject SQL syntax by providing input like `' OR '1'='1` to manipulate the query logic.

The fix replaces the concatenation-based approach with a parameterized query using `PreparedStatement`. The `?` placeholder ensures that the user input is treated as data, not executable SQL code. The `setString()` method binds the data to the parameter, preventing the database driver from interpreting it as query structure. This is the primary defence against SQL injection in JDBC applications.

## Behaviour changes

The change from `Statement.createStatement()` to `PreparedStatement.prepareStatement()` alters the execution model: the prepared statement is created once with a fixed query structure, then parameters are bound separately on each execution. This does not change the visible output or error handling - `executeQuery()` still returns a `ResultSet`, and `SQLException` is still thrown on database errors. The resource cleanup in the finally block remains the same. No functional changes beyond closing the injection point.

