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
The decoded `BenchmarkTest00018` header was concatenated straight into the `VALUES` clause and executed through `Statement.executeUpdate(sql)`, so a quote in the header closed the literal and let the remainder of the header be parsed as SQL. The query is now a fixed string in which the untrusted value is represented by a `?` placeholder, and the header is supplied separately via `PreparedStatement.setString(1, param)` on a statement obtained from `connection.prepareStatement(sql)`; the no-argument `executeUpdate()` overload is used so the raw string is never re-submitted. The driver sends the statement text and the bound value on separate paths, so the value is only ever interpreted as column data no matter what quotes, comments, or statement separators it contains, and the surrounding single quotes are dropped because the binding supplies the literal itself. Payloads such as `' OR '1'='1` or `'); DROP TABLE users;--` are stored verbatim as a password value rather than altering the statement.
