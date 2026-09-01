## Verdict

**Confirmed**: CWE-89 SQL Injection at line 60.

The application constructs a SQL INSERT statement by concatenating unsanitized user input directly into the query string, then executes it via `statement.executeUpdate()`.

## Source

HTTP request header `BenchmarkTest00018` at lines 45-48:
```java
java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");
if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement();
}
```

The value is URL-decoded at line 52 but remains untrusted.

## Fix

Replace the concatenated SQL string with a parameterized query using `PreparedStatement` and `?` placeholders:

**Current vulnerable pattern (lines 54, 60):**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
int count = statement.executeUpdate(sql);
```

**Fixed pattern:**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";
java.sql.PreparedStatement pstmt = org.owasp.benchmark.helpers.DatabaseHelper.getPreparedStatement(sql);
pstmt.setString(1, param);
int count = pstmt.executeUpdate();
```

The `DatabaseHelper.getSqlStatement()` call should be replaced with a method that returns a `PreparedStatement` for the parameterized query, or `prepareStatement()` should be called on the underlying connection object.

## Explanation

The vulnerability exists because user input from the HTTP header is directly interpolated into a SQL query string via concatenation. An attacker can break out of the string literal by injecting a single quote, then append arbitrary SQL syntax (e.g., `' OR '1'='1` or `'; DROP TABLE users; --`).

The fix uses parameterized queries (prepared statements) which enforce a separation between SQL structure and data. The `?` placeholder marks a data position, and `setString()` binds the user input as a value only, never as executable SQL code. This prevents injection regardless of what characters the input contains.

## Behaviour changes

- Query construction changes from string concatenation to parameterized placeholders
- The `param` value is now passed to `setString()` rather than concatenated into the SQL string
- All user input is guaranteed to be treated as literal data, never as SQL syntax
- The query structure is fixed at statement preparation time and cannot be altered by input data
