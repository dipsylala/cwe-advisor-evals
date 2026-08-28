## Fix

```java
    // Only these stored procedures may be invoked, and each has a fixed,
    // developer-authored call string. Request data selects an entry; it never
    // contributes to the SQL text.
    private static final java.util.Map<String, String> ALLOWED_PROCEDURES;

    static {
        java.util.Map<String, String> procs = new java.util.HashMap<>();
        procs.put("getUser", "{call getUser(?)}");
        procs.put("listUsers", "{call listUsers()}");
        ALLOWED_PROCEDURES = java.util.Collections.unmodifiableMap(procs);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = ALLOWED_PROCEDURES.get(param);
        if (sql == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown operation.");
            return;
        }

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);

            // Any procedure argument is bound as a parameter, never concatenated.
            if (statement.getParameterMetaData().getParameterCount() > 0) {
                String arg = request.getParameter("arg");
                statement.setString(1, arg == null ? "" : arg);
            }

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

The original code built the callable-statement text by concatenating the attacker-controlled `BenchmarkTest00008` header into `"{call " + param + "}"`, so the header could terminate the call and append arbitrary SQL that the driver then parsed and executed. Because the injected value here is the procedure name itself, it occupies a position in the statement that a bind parameter cannot represent; the fix is therefore an allowlist. The header value is now used only as a lookup key into a fixed map of developer-authored call strings, and a value that is not a key yields a 400 rather than reaching the database, so the SQL sent to `prepareCall` is always one of a known, constant set of statements. Any procedure argument is supplied through `setString`, where the driver treats it as data rather than as statement syntax, keeping the data-position input parameterized as well. The result is that no part of the executed SQL text can originate from request data, which removes the injection at its root instead of relying on escaping or filtering.
