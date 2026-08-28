## Fix

```java
    // Only these stored procedures may be invoked through this endpoint.
    private static final java.util.Set<String> ALLOWED_PROCEDURES =
            java.util.Collections.unmodifiableSet(
                    new java.util.HashSet<String>(
                            java.util.Arrays.asList("getUserById", "listUsers")));

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        // A procedure name is query structure, not a bindable value, so it must be resolved
        // against a fixed allowlist rather than concatenated in from the request.
        if (!ALLOWED_PROCEDURES.contains(param)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Error processing request.");
            return;
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
    }
```

## Explanation

The `BenchmarkTest00008` request header was URL-decoded and concatenated straight into the `{call ...}` escape sequence, so the caller controlled the identifier and could append arbitrary statement text that `prepareCall` then compiled and `executeQuery()` ran. A `?` placeholder cannot fix this position: placeholders bind values, and a stored-procedure name is query structure, so the driver would reject it. The remediation instead resolves the requested name against a fixed, server-side allowlist of permitted procedures before any SQL is built, and rejects the request with a generic error otherwise. After the check the only strings that can reach the concatenation are compile-time constants from that set, so the untrusted header can no longer influence the parsed statement. Any procedure arguments added later must still be passed as `?` placeholders bound with `setString()`/`setInt()` rather than concatenated, and the database account should hold only the execute privileges these procedures need.
