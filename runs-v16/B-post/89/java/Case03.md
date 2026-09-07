## Verdict

Exploitable

## Source

The `data` parameter passed to the `handleSink()` method. This is user-controlled input, originating from an HTTP request context.

## Fix

**Vulnerable code (line 28):**
```java
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**
```java
PreparedStatement pstmt = dbConnection.prepareStatement("select * from users where name=?");
pstmt.setString(1, data);
resultSet = pstmt.executeQuery();
```

Additionally, update the finally block resource cleanup to close the `PreparedStatement`:
```java
try
{
    if (pstmt != null)
    {
        pstmt.close();
    }
}
catch (SQLException exceptSql)
{
    IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
}
```

## Explanation

The vulnerability exists because user-supplied `data` is concatenated directly into the SQL query string without parameterization. This allows attackers to inject SQL metacharacters (such as `'`, `--`, or `OR`) to manipulate query logic, bypass authentication, or access unauthorized data.

The fix replaces string concatenation with a `PreparedStatement` that uses a `?` placeholder. The `setString()` method binds the untrusted input as a parameter value, not as query structure. The SQL parser treats everything after `setString()` as literal data, preventing injection. This is the standard, recommended defence in Java JDBC: parameterized queries separate query structure from data.

## Behaviour changes

- `sqlStatement.createStatement()` is replaced with `dbConnection.prepareStatement()`, which compiles the SQL template ahead of time with a placeholder
- `executeQuery()` is called on `PreparedStatement` instead of `Statement` (no argument, as the query was already compiled by `prepareStatement()`)
- The `ResultSet` return type and usage remain unchanged
- The finally block must close `pstmt` instead of `sqlStatement` to close the correct resource type
- No other logic changes; the query's structure and result handling remain identical

All new methods (`prepareStatement`, `setString`) are part of the Java standard library (`java.sql` package, already imported). No additional dependencies required.
