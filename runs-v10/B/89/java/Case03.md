## Verdict

**Exploitable SQL Injection vulnerability.** User-supplied name parameter flows unsanitized from `HttpServletRequest` through a 5-method call chain to a SQL query concatenation sink. An attacker can inject SQL metacharacters to manipulate query logic, extract unauthorized data, or modify records.

## Source

User input originates in `Case03A.handleSink()` via `request.getParameter("name")` (line 15), then flows through intermediary methods in Case03B, Case03C, and Case03D before reaching the sink in Case03E.

## Fix

Replace string concatenation with parameterized query using `PreparedStatement`:

**Vulnerable code (Case03E.java, lines 24–28):**
```java
sqlStatement = dbConnection.createStatement();

// SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**
```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);

resultSet = sqlStatement.executeQuery();
```

Also update the variable declaration on line 18 from `Statement` to `PreparedStatement`:
```java
PreparedStatement sqlStatement = null;
```

## Explanation

The fix replaces the vulnerable `Statement.createStatement()` and concatenated query with `PreparedStatement.prepareStatement()` using a `?` placeholder for the user-supplied name value. The `setString()` call binds the untrusted input as a parameter value, not as query structure. This ensures the database driver treats the entire input as a literal string value, preventing SQL metacharacter injection. The `executeQuery()` call now takes no arguments since the complete prepared statement already contains both the query structure and bound parameters.

## Behaviour changes

- **Query execution timing**: Parameter binding now occurs before database transmission, not during string construction
- **Type enforcement**: `setString()` explicitly declares the parameter as string type to the driver
- **Null handling**: If `data` is null, the bound parameter becomes SQL NULL; string concatenation would have produced the literal string "null"
- **Error reporting**: SQLException now includes driver-level feedback on type mismatches if the binding fails
- **Performance**: Prepared statements are typically cached by the database, enabling query plan reuse across multiple calls with different parameter values
