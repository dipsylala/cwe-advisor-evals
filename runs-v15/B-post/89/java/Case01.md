## Verdict

Exploitable. The user-controlled `name` parameter from the HTTP request is concatenated directly into a SQL query string without parameterization, allowing SQL injection.

## Source

`Case01A.java`, line 15: `data = request.getParameter("name");`

The `name` request parameter is received from the client and passed untrusted to the sink.

## Fix

**Vulnerable code (Case01B.java, lines 24 and 28):**

```java
sqlStatement = dbConnection.createStatement();
// ...
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**

```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation

The fix replaces string concatenation with `PreparedStatement` and parameterized queries. The SQL structure is fixed in the query string with a `?` placeholder, and the untrusted `name` parameter is bound separately using `setString()`, which treats it as data only, never as query structure. This prevents the attacker from injecting SQL operators or logic. The `PreparedStatement` is created with `prepareStatement()` instead of `createStatement()`, and the parameter is bound before `executeQuery()` is called with no arguments.

## Behaviour changes

None. The `ResultSet` return type and the query semantics are preserved. The statement still throws `SQLException` on error as before. The resource cleanup in the finally block remains unchanged because the same exception types are thrown.
