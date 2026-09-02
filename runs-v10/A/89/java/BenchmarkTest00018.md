## Verdict

SQL Injection via unvalidated HTTP header input directly concatenated into a SQL INSERT statement. Confirmed at line 60 where `statement.executeUpdate(sql)` executes a query built from untrusted data.

## Source

User-supplied data flows from HTTP header to SQL:

1. Line 45: `request.getHeaders("BenchmarkTest00018")` retrieves header value
2. Line 52: URL-decoded but not sanitized for SQL context
3. Line 54: Directly concatenated into SQL string: `"INSERT INTO users (username, password) VALUES ('foo','" + param + "')"` 
4. Line 60: **Sink** — `statement.executeUpdate(sql)` executes the malicious query

An attacker controlling the `BenchmarkTest00018` header can inject SQL metacharacters to alter query logic, such as: `'; DROP TABLE users; --`

## Fix

Replace string concatenation with a parameterized query using `PreparedStatement`:

```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";
java.sql.PreparedStatement statement = 
    org.owasp.benchmark.helpers.DatabaseHelper.getSqlPreparedStatement(sql);
statement.setString(1, param);
int count = statement.executeUpdate();
org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
```

The parameterized approach separates SQL structure from data. The `?` placeholder marks where user input belongs, and `setString()` binds the value safely, ensuring it is treated as data only and not executable SQL code.

## Explanation

SQL injection occurs because the code treats user input as part of the SQL command structure rather than as data. String concatenation allows special characters in the input to close the string literal and inject new SQL tokens.

Parameterized queries defend against this by using placeholders for all variable data. The SQL parser receives the query template first, then the data is bound separately through a type-safe API. This ensures the database engine cannot interpret user input as SQL syntax, regardless of what characters it contains.
