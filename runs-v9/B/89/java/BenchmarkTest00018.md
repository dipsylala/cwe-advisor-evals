## Verdict

exploitable

- cwe_id: CWE-89
- location: BenchmarkTest00018.java, line 60 (`statement.executeUpdate(sql)`)
- confidence: high

## Source

`request.getHeaders("BenchmarkTest00018")` (line 45) - the first value of an attacker-controlled HTTP request header, URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`). URL-decoding does not neutralize SQL metacharacters (e.g. `'`), so the value reaching the sink is still fully attacker-controlled.

## Fix

Vulnerable code:

```java
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";

try {
    java.sql.Statement statement =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
    // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
    int count = statement.executeUpdate(sql);
    org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
} catch (java.sql.SQLException e) {
    if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
    } else throw new ServletException(e);
}
```

Fixed code:

```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.PreparedStatement statement = connection.prepareStatement(sql);
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

The `password` value was concatenated directly into the SQL text, so a header value containing `','attacker@x.com'); --` (or similar) closes the string literal and rewrites the statement's structure - the classic SQL injection path into `Statement.executeUpdate()`. The fix replaces the literal-in-string with a `?` placeholder and moves `param` to a bound parameter via `PreparedStatement.setString()`, so the driver always treats it as a single data value regardless of its contents, never as SQL syntax. The `username` column stays a fixed literal (`'foo'`) since it is not attacker-influenced here, so no additional placeholder is needed for it.

## Behaviour changes

- Statement acquisition changed from `DatabaseHelper.getSqlStatement()` (a plain `Statement`) to `DatabaseHelper.getSqlConnection().prepareStatement(sql)` (a `PreparedStatement`), which is required to use bound parameters instead of string concatenation. This assumes `DatabaseHelper` exposes a `getSqlConnection()` method returning the same underlying `java.sql.Connection` used by `getSqlStatement()`; that method was not visible in the supplied file, so its exact name/signature could not be confirmed from the code in scope - confirm against the actual `DatabaseHelper` source before applying.
- `executeUpdate(sql)` (statement-level, taking the SQL text) became `executeUpdate()` (prepared-statement-level, no arguments) since the SQL is now bound to the `PreparedStatement` object at creation time. The return value (`count`, the affected-row count) and its type are unchanged.
- `sql` passed to `DatabaseHelper.outputUpdateComplete(sql, response)` is now the parameterized template (`... VALUES ('foo', ?)`) rather than the fully-substituted string; if that helper echoes `sql` back to the response for display purposes, the displayed text will show `?` instead of the submitted password. This is expected: echoing back attacker-controlled data as previously done would itself be worth checking separately, but no change was made to `outputUpdateComplete` itself here.
- All other logic - error handling, `hideSQLErrors` branching, response content type - is unchanged.
