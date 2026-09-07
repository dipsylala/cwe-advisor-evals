## Verdict
exploitable

## Source
`request.getParameter("name")` at Case01A.java:15, passed as `data` parameter to Case01B.handleSink()

## Fix

**Vulnerable Code (Case01B.java, lines 18, 24, 28):**
```java
Statement sqlStatement = null;
// ...
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed Code:**
```java
PreparedStatement sqlStatement = null;
// ...
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation
The vulnerability arises from concatenating untrusted user input (`data`) directly into the SQL query string on line 28. An attacker can inject SQL metacharacters like `' OR '1'='1` to manipulate the query logic and bypass authentication or access unauthorized data. The fix replaces string concatenation with a parameterized query using a `PreparedStatement`. The `?` placeholder marks the position where user data should be inserted, and `setString(1, data)` binds the untrusted value as a parameter. This ensures the database driver treats the input as data only, never as executable SQL code, eliminating the injection vector.

## Behaviour changes
The variable declaration changes from `Statement sqlStatement` to `PreparedStatement sqlStatement` (line 18). This is required because parameterized queries can only be executed through the `PreparedStatement` API, which provides the `setString()` method for safe parameter binding. The `executeQuery()` call changes from taking the query string as an argument to taking no arguments (line 28), because the query is now prepared with placeholders at statement creation time. These changes are internal to the sink and do not affect the contract with the caller - the method still returns the same `ResultSet` and maintains the same error handling and resource cleanup logic.
