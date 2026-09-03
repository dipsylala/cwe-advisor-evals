## Verdict

exploitable

## Source

The `data` parameter passed to the `handleSink()` method at line 14, originating from untrusted HTTP request data (indicated by the `HttpServletRequest` parameter in the method signature). The parameter is used without any sanitization or parameterization before reaching the SQL sink.

## Fix

**Vulnerable code (line 24, 28):**
```java
sqlStatement = dbConnection.createStatement();
// ...
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**
```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
((PreparedStatement)sqlStatement).setString(1, data);
// ...
resultSet = sqlStatement.executeQuery();
```

## Explanation

The vulnerability arises from string concatenation building the SQL query directly with untrusted input. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) to manipulate query logic and bypass authentication or access unauthorized data.

The fix replaces the unsafe `Statement.executeQuery()` with a `PreparedStatement` that uses a parameterized query. The `?` placeholder separates SQL structure from data values, and the `setString()` method binds the untrusted input as a data-only value. This ensures that the database driver always treats the input as data, not as executable SQL code, eliminating injection attacks regardless of the input content.

## Behaviour changes

The only difference in behaviour is the change from string concatenation to parameterized binding:

- **Query execution method**: Changed from `executeQuery(String sql)` to `executeQuery()` (no arguments) because the SQL is now prepared separately with placeholders bound via `setString()`. This is the required usage pattern for `PreparedStatement`.
- **Type cast**: The code casts `sqlStatement` to `PreparedStatement` to access the `setString()` method. This is necessary since the variable is declared as `Statement` in the original code. Alternatively, the declaration could be changed to `PreparedStatement sqlStatement = null;` to eliminate the cast, but the current approach minimizes changes to the existing structure.
- **No change to return value**: The `ResultSet` is still returned from `executeQuery()` with the same semantics and behavior as before.

