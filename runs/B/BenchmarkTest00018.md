## Fix

```java
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

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
    }
```

## Explanation

The `BenchmarkTest00018` header value was URL-decoded and concatenated inside a quoted literal in the `INSERT` text, so a payload containing a single quote could close that literal and have the rest of its content parsed as SQL by `Statement.executeUpdate(sql)`. The query is now a constant string whose value position is a `?` placeholder, executed through a `PreparedStatement` obtained from `Connection.prepareStatement()`, with the header bound by `setString(1, param)` and the no-argument `executeUpdate()` used so no built string reaches the driver. Because the statement is parsed before the parameter is supplied, the header can only ever be stored as a literal value, whatever characters it contains, and the fix holds without escaping or filtering the input. The bound value stays untrusted data for later use, so any query that reads this row back must parameterize it too rather than concatenating it, and the SQL echoed by `outputUpdateComplete` is now the placeholder form rather than the interpolated one.
