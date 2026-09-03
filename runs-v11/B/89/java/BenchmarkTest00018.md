## Verdict

Exploitable SQL Injection via untrusted request header.

## Source

Request header `BenchmarkTest00018` (line 45-48), URL-decoded (line 52).

## Fix

```java
String param = "";
java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");

if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement();
}

param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";

try {
    java.sql.Connection conn = org.owasp.benchmark.helpers.DatabaseHelper.getConnection();
    java.sql.PreparedStatement statement = conn.prepareStatement(sql);
    statement.setString(1, param);
    int count = statement.executeUpdate();
    org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
} catch (java.sql.SQLException e) {
    if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
    } else throw new ServletException(e);
}
```

## Explanation

The original code concatenated untrusted header data directly into a SQL string (line 54), allowing an attacker to inject SQL syntax via the header value. The fix replaces string concatenation with a `PreparedStatement` using a `?` placeholder for the value. The untrusted parameter is bound via `setString(1, param)`, which treats it as literal data rather than executable SQL structure. The parameterized query prevents the injected input from being interpreted as SQL syntax regardless of its content.

## Behaviour changes

- Replaced `Statement` with `PreparedStatement` obtained via `conn.prepareStatement(sql)`.
- Changed SQL string from `"... VALUES ('foo','" + param + "')"` to `"... VALUES ('foo', ?)"`.
- Added `statement.setString(1, param)` to bind the parameter value.
- Requires obtaining a `Connection` object from `DatabaseHelper.getConnection()` instead of using `getSqlStatement()` directly.
- Return value and exception handling remain unchanged; `executeUpdate()` still returns the affected row count and throws `SQLException`.
