## Verdict

Exploitable - SQL Injection vulnerability confirmed via parameterized query bypass.

## Source

HTTP request header `BenchmarkTest00018` (line 45) flows through URL decoding (line 52) into the `param` variable, which is then directly concatenated into a SQL INSERT query without parameterization.

## Fix

### File: BenchmarkTest00018.java

```java
/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00018")
public class BenchmarkTest00018 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

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
            // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
            int count = statement.executeUpdate();
            org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    }
}
```

## Explanation

The original code built a SQL query by concatenating the untrusted HTTP header value directly into the query string, allowing an attacker to inject SQL operators and logic. The fix eliminates this by:

1. Replacing the concatenated SQL string with a parameterized query using `?` placeholder (line 54)
2. Obtaining a `Connection` via `DatabaseHelper.getSqlConnection()` instead of a bare `Statement` (lines 57-58)
3. Creating a `PreparedStatement` from the connection with the parameterized SQL (line 59)
4. Binding the untrusted user input as a string parameter using `setString(1, param)` (line 60)
5. Executing the prepared statement without arguments (line 62)

This ensures the user input is always treated as data, never as executable SQL code. The database driver separates the SQL structure (defined by the prepared statement) from the data (bound via `setString()`), making injection impossible.

## Behaviour changes

None - the fix preserves the original contract:
- **Returns**: `executeUpdate()` still returns the number of affected rows, bound to `count` exactly as before
- **Arguments**: The SQL string passed to the database is still the parameterized template with `?` in place of values; the injected user data is now transmitted separately as a string parameter
- **Failure behaviour**: SQL exceptions are caught and handled identically to the original - either silently logged or re-thrown as `ServletException`
- **Invocation model**: The `outputUpdateComplete()` call receives the parameterized SQL string (with `?` placeholders, not the literal user input), which is appropriate for logging safe-to-display query templates

