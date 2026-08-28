## Fix

```java
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00018");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "INSERT INTO users (username, password) VALUES (?, ?)";

        try (java.sql.Connection connection =
                        org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
                java.sql.PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, "foo");
            statement.setString(2, param);

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

The original code interpolated the attacker-controlled `BenchmarkTest00018` header directly into the `VALUES` clause of an `INSERT`, so a header containing a single quote could close the literal and have the remainder of its content parsed as SQL by `Statement.executeUpdate`. The rewritten version makes the statement text a fixed string containing `?` placeholders and switches from `java.sql.Statement` to `java.sql.PreparedStatement`, binding the constant username and the header-derived password with `setString`. The driver sends the statement and its parameters separately, so the bound values are only ever interpreted as column data and quoting or escaping characters inside them carry no syntactic meaning - the injection is eliminated regardless of what the header contains, with no reliance on input filtering. The statement is obtained from a connection in a try-with-resources block so the prepared statement and connection are closed on every path, replacing the shared `getSqlStatement()` helper whose `Statement` type cannot carry bind parameters.
