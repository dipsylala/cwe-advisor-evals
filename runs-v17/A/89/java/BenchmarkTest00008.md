## Verdict
Confirmed SQL injection vulnerability. User-controlled input from HTTP header is directly concatenated into a SQL callable statement without parameterization.

## Source
Line 52: `String sql = "{call " + param + "}";` concatenates the unsanitized `param` directly into the SQL string.
Line 46: `param` originates from an untrusted HTTP header (`request.getHeader("BenchmarkTest00008")`).
Line 50: URL decoding does not prevent SQL injection; it only decodes the format of the input.
Line 57: `connection.prepareCall(sql)` treats the concatenated string as the statement, bypassing parameterization.
Line 59: `statement.executeQuery()` is the sink where the injection is executed.

## Fix
### File: BenchmarkTest00008.java

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

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {

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
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "{call testprocedure(?)}";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            statement.setString(1, param);
            // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
            java.sql.ResultSet rs = statement.executeQuery();
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);

        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    }
}
```

## Explanation
The vulnerability was introduced by concatenating unsanitized HTTP header input directly into a SQL callable statement string (line 52 of the original code). Even though `prepareCall()` is used, it was passed a concatenated string rather than a parameterized query, eliminating its protective effect.

The fix replaces the direct concatenation with a parameterized approach:
- Line 52 (fixed): `String sql = "{call testprocedure(?)}";` defines the SQL with a `?` placeholder instead of concatenating the parameter
- Line 58 (new): `statement.setString(1, param);` binds the user input as a parameter using the type-safe setter method

This ensures the database driver treats the user input as data, not as executable SQL code, preventing SQL injection attacks. The parameter binding separates the SQL structure from the data, which is the fundamental defense against SQL injection.
