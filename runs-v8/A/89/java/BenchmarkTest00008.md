## Verdict
SQL Injection via callable statement. User-controlled input from HTTP header is concatenated directly into a SQL command string before being passed to `prepareCall()`, allowing an attacker to inject arbitrary SQL code.

## Source
Line 52 constructs the SQL string by concatenating unsanitized user input (`param`) derived from an HTTP header into a callable statement template:
```
String sql = "{call " + param + "}";
```
This concatenated string is then passed to `connection.prepareCall(sql)` at line 57. The `prepareCall()` method parses the SQL string for its statement structure, so injection occurs before parameterization takes place.

## Fix
Validate the input against a whitelist of allowed stored procedure names before using it:

```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

param = java.net.URLDecoder.decode(param, "UTF-8");

// Whitelist validation: only allow known procedure names
java.util.Set<String> allowedProcedures = new java.util.HashSet<>(
    java.util.Arrays.asList("proc_get_users", "proc_validate_data")
);

if (!allowedProcedures.contains(param)) {
    throw new ServletException("Invalid procedure name");
}

String sql = "{call " + param + "}";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
} catch (java.sql.SQLException e) {
    if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        response.getWriter().println("Error processing request.");
    } else throw new ServletException(e);
}
```

Alternatively, if `param` is meant to be a parameter passed to the stored procedure rather than the procedure name itself, restructure to use parameter binding:

```java
String sql = "{call known_procedure_name(?)}"
java.sql.CallableStatement statement = connection.prepareCall(sql);
statement.setString(1, param);
java.sql.ResultSet rs = statement.executeQuery();
```

## Explanation
The vulnerability exists because `prepareCall()` requires a fully-formed SQL string—it cannot use parameter placeholders for the stored procedure name itself, only for the parameters passed to the procedure. Concatenating user input into the SQL string before calling `prepareCall()` allows an attacker to break out of the intended command structure and inject arbitrary SQL.

The fix uses a whitelist to restrict the procedure name to known, safe values. If parameters need to be passed to the procedure, use the `setString()`, `setInt()`, or other setter methods on the `CallableStatement` to bind values safely, keeping the procedure name constant in the SQL string.
