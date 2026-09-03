## Verdict

SQL injection vulnerability confirmed. The `data` parameter from the HTTP request is concatenated directly into the SQL query string without validation or escaping, allowing an attacker to inject arbitrary SQL commands.

## Source

The vulnerability originates in Case01A.java:
- Line 15: `data = request.getParameter("name");` — untrusted user input from HTTP request

The tainted data flows to Case01B.java and is used unsafely in the SQL query.

## Fix

Replace the string concatenation approach with a parameterized query using `PreparedStatement`:

**Original (vulnerable):**
```java
Statement sqlStatement = null;
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed:**
```java
PreparedStatement sqlStatement = null;
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation

A `PreparedStatement` separates SQL syntax from user-supplied data. The `?` placeholder is a parameter marker; the database driver binds the actual value through `setString()`, treating it as data rather than executable SQL code. This prevents the attacker from breaking out of the string literal or injecting SQL operators. The fix maintains the same query logic while eliminating the injection vector.
