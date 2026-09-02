## Verdict

Confirmed. The header value `param` (from `request.getHeaders("BenchmarkTest00018")`, URL-decoded) is concatenated directly into the SQL text and executed via `java.sql.Statement.executeUpdate(sql)`, allowing SQL injection through the HTTP header.

## Source

`doPost` reads the `BenchmarkTest00018` request header:

```java
java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");
if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement();
}
param = java.net.URLDecoder.decode(param, "UTF-8");
```

This value flows unmodified into the SQL string built on line 54 and reaches the sink at line 60.

## Fix

Replace the `Statement`/string-concatenation with a `PreparedStatement` that binds `param` as a parameter instead of splicing it into the SQL text:

```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    try (java.sql.PreparedStatement statement = connection.prepareStatement(sql)) {
        statement.setString(1, param);
        // SAST FINDING (fixed): SQL statement now uses a parameterized query.
        int count = statement.executeUpdate();
        org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
    }
} catch (java.sql.SQLException e) {
    if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
    } else throw new ServletException(e);
}
```

If the helper class only exposes a ready-made `Statement` (as in the original code) rather than a `Connection`, obtain the underlying `Connection` from it (e.g. `statement.getConnection()`) and call `prepareStatement` on that, or add/use a helper method that returns a `Connection` directly. The key change is that the literal SQL text passed to the driver contains a `?` placeholder in place of the attacker-controlled value, and `param` is bound afterward through `setString`, so it can never be interpreted as SQL syntax regardless of its content.

## Explanation

`Statement.executeUpdate(String)` sends the exact string it is given to the database for parsing and execution, so any SQL metacharacters (quotes, comment markers, statement separators) inside `param` are interpreted as part of the query. Because `param` comes straight from a client-supplied HTTP header (and is even URL-decoded first, undoing one layer of encoding an attacker could use to smuggle characters past naive filters), an attacker can close the string literal early and append arbitrary SQL — for example additional `INSERT`/`UPDATE` statements or a `UNION`-based read, depending on what the driver/database allows in a batched or stacked query.

`PreparedStatement` closes this off structurally rather than by filtering: the SQL text is compiled once with the `?` placeholder as a fixed operand position, and the driver sends `param`'s value to the database as pure data over a separate channel from the query plan. No value bound through `setString` can alter the statement's structure, so quotes, semicolons, or comment sequences inside the header are treated as literal characters of the `password` value, not as SQL syntax. This removes the injection vector while preserving the original behavior (inserting the row using the caller-supplied value) for all legitimate inputs.
