## Verdict

**Confirmed SQL Injection (CWE-89)**. The application directly concatenates untrusted user input from an HTTP request parameter into a SQL query string, enabling attackers to inject arbitrary SQL commands.

## Source

**Case01A.java, line 15 (source) → Case01B.java, line 28 (sink)**

The `data` variable is obtained from `request.getParameter("name")` without validation. This unsanitized user input flows directly into a SQL query constructed by string concatenation:

```
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

An attacker can inject SQL metacharacters—such as a single quote followed by `OR 1=1` or a `UNION` clause—to alter query logic, extract unauthorized data, or modify the database.

## Fix

Replace the vulnerable `Statement` with a `PreparedStatement`, using parameter binding:

```java
// Instead of:
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");

// Use:
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
((PreparedStatement)sqlStatement).setString(1, data);
resultSet = sqlStatement.executeQuery();
```

Alternatively, declare `sqlStatement` as `PreparedStatement` from the start:

```java
PreparedStatement sqlStatement = null;
...
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation

Prepared statements separate SQL structure from data. The query template is parsed once at prepare time; parameter values are transmitted separately and treated as data, not executable SQL. An attacker cannot inject SQL syntax through a parameter value because the database driver escapes or treats it literally.

This approach:
- Prevents SQL injection by eliminating string concatenation with user input
- Is the standard Java solution for parameterized queries
- Requires only `?` placeholders in the query and corresponding `setString()` (or other type-specific setter) calls matching the parameter positions
- Works with all JDBC drivers and SQL dialects
