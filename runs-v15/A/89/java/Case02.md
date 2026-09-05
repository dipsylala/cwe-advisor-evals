## Verdict

**Confirmed: CWE-89 SQL Injection** at line 28 of Case02D.java. User-controlled data from the HTTP request parameter is directly concatenated into a SQL query string without parameterization, allowing arbitrary SQL code injection.

## Source

Line 28 of Case02D.java:
```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

The `data` parameter originates from `request.getParameter("name")` in Case02A and flows through Case02B and Case02C without validation or sanitization before reaching the SQL sink.

## Fix

Replace the string concatenation with a parameterized query using `PreparedStatement`:

```java
dbConnection = IO.getDBConnection();
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);
resultSet = preparedStatement.executeQuery();
```

Then update the finally block to close `preparedStatement` instead of `sqlStatement`.

## Explanation

Parameterized queries (also called prepared statements) separate the SQL code structure from the data. The database engine knows exactly where user input can appear and treats it as data, not executable SQL. This prevents injection attacks regardless of what characters or SQL keywords the attacker includes in the input. The `?` placeholder marks the position, and `setString()` binds the user data safely to that parameter, ensuring the database driver handles escaping and encoding correctly.

