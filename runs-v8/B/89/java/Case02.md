## Verdict

**Exploitable SQL Injection confirmed.** Untrusted user input from `request.getParameter("name")` flows through the call chain (Case02A → Case02B → Case02C) to Case02D line 28, where it is concatenated directly into a SQL query executed via `Statement.executeQuery()`.

**Attack scenario:** Input `' OR '1'='1` transforms the query to `select * from users where name='' OR '1'='1'`, returning all user records.

## Source

User input enters via HTTP parameter in Case02A:
```
data = request.getParameter("name");  // Case02A line 15
```

This untrusted value is passed unchanged through Case02B and Case02C to Case02D.

## Fix

Replace line 28 in Case02D with a parameterized query using `PreparedStatement`:

**Original (vulnerable):**
```java
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed:**
```java
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);
resultSet = preparedStatement.executeQuery();
```

Update the variable declarations at the top of the method to use `PreparedStatement`:

**Original:**
```java
Statement sqlStatement = null;
```

**Fixed:**
```java
PreparedStatement sqlStatement = null;
```

Then update the cleanup logic to close the PreparedStatement correctly (this remains compatible with the existing finally block since PreparedStatement extends Statement).

## Explanation

The fix converts the vulnerable string concatenation into a parameterized query. The SQL structure (`select * from users where name=?`) is fixed and known to the database driver, while the `?` placeholder is filled by `setString(1, data)`, which treats the input as pure data, not executable SQL. This prevents the attacker from injecting SQL operators or keywords because the data is never parsed as query structure—it is only ever a value to be matched.

This satisfies the sink contract: `executeQuery()` returns the same `ResultSet`, the query executes normally, and error handling via `SQLException` remains unchanged.

## Behaviour changes

- Query execution now uses `PreparedStatement` instead of `Statement` for parameterized binding.
- The SQL string is static and no longer constructed at runtime; it is prepared once with the parameter placeholder.
- Input validation via parameterization is applied at the database driver level; no application-side escaping is needed.
- Performance may improve slightly on repeated executions of the same prepared statement (driver-level caching), though this code path creates a new statement each time.
- No functional change to the returned data or exception handling—the query logic and error reporting remain identical.
