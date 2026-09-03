## Verdict
exploitable

## Source
Case01A.java, line 15: `data = request.getParameter("name");`

Untrusted user input from the HTTP request parameter is passed to the sink without validation or parameterization.

## Fix

**Vulnerable Code (Case01B.java, line 28):**
```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed Code:**
```java
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);
resultSet = preparedStatement.executeQuery();
```

## Explanation

The fix replaces string concatenation with a `PreparedStatement` and parameterized query. The `?` placeholder marks the position where user input is bound, ensuring the `data` parameter is treated as a value, not as executable SQL code. The `setString()` method explicitly binds the untrusted input as a string parameter. This prevents SQL injection attacks such as `' OR '1'='1` from altering query logic. The `PreparedStatement` must be created from the connection before the query is prepared; passing the concatenated string to `prepareStatement()` is already injected and unsafe.

## Behaviour changes

The `sqlStatement` is replaced by `preparedStatement` for this specific query. The `ResultSet` returned by `executeQuery()` behaves identically to the original. Resource management is simplified because `preparedStatement` does not need separate closing in this scope (the existing finally block closes `sqlStatement`, which should be updated to close `preparedStatement` instead). The query execution fails with the same SQLException behavior if there is a database error. No other aspects of the application flow are affected.
