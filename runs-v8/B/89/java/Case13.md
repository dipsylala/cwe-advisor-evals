## Verdict

Exploitable. The `data` parameter is concatenated directly into the SQL query string without parameterization or validation, allowing an attacker to inject SQL code.

## Source

`data` parameter passed from Case13A (line 15: `data = "foo"`) to Case13B.handleSink() method (line 14). While the test case uses a hardcoded value, the method signature accepts untrusted input that could be derived from request parameters at runtime.

## Fix

**Vulnerable code (Case13B.java, lines 24-28):**

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

## Explanation

The fix replaces string concatenation with a parameterized query using `PreparedStatement`. The SQL template is prepared separately with a `?` placeholder for the user-supplied `data` value. The `setString(1, data)` call binds the untrusted input as a parameter value, ensuring it is treated as data rather than SQL code. The `executeQuery()` call no longer receives the query string as an argument since it was already bound during statement preparation. This prevents SQL injection by ensuring the database driver parses the query structure and parameters separately.

## Behaviour changes

- Line 24: Changed from `dbConnection.createStatement()` to `dbConnection.prepareStatement(String)`. The prepareStatement method takes the SQL template as an argument and returns a PreparedStatement rather than a Statement. This is required for parameter binding.
- Line 27-28: Removed the SQL string argument from `executeQuery()` call. A PreparedStatement's `executeQuery()` method does not take a query string parameter; the query was already supplied and compiled during preparation. This is the standard contract for parameterized queries in JDBC.
- Added line 26: `sqlStatement.setString(1, data)` to bind the untrusted parameter value. This is required to safely pass user input to the prepared statement.
