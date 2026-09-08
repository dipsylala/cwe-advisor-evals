## Verdict

**Confirmed**: SQL injection vulnerability in line 60. Untrusted HTTP header data flows through URL decoding (line 52) into string concatenation (line 54) and is executed in an `executeUpdate()` call (line 60) without parameterization.

## Source

HTTP request header `BenchmarkTest00018` (line 45, `request.getHeaders("BenchmarkTest00018")`). Headers are attacker-controlled. The value is URL-decoded (line 52) but remains untrusted. Line 54 concatenates it directly into a SQL string without any parameterization or escaping.

## Fix

Replace the string-concatenated SQL statement with a `PreparedStatement` using a `?` placeholder. Bind the untrusted parameter via `setString()` to ensure it is treated as data, not SQL structure.

**Assumption**: `DatabaseHelper.getConnection()` is available to retrieve a database connection. This follows standard JDBC patterns used elsewhere in the codebase.

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
                    org.owasp.benchmark.helpers.DatabaseHelper.getConnection();
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
}
```

## Explanation

The vulnerability is eliminated by using a `PreparedStatement` instead of string concatenation. The SQL structure is fixed as `"INSERT INTO users (username, password) VALUES ('foo', ?)"` with a single placeholder. The untrusted `param` value is bound via `setString(1, param)`, which tells the JDBC driver to treat it as a literal data value, not as executable SQL code. This blocks all SQL injection attacks regardless of the content of `param` — special characters like `'`, `--`, `/**/`, and SQL keywords are all neutralized because they are no longer part of the query structure.

The fix preserves the original behavior:
- Returns the same integer count of affected rows
- Throws the same `SQLException` on database errors
- Maintains error handling and the `hideSQLErrors` check
- Passes the sanitized SQL string (with placeholder) to `outputUpdateComplete()` for logging/output

## Behaviour changes

None. The fix is a drop-in replacement that produces identical application behavior (same INSERT, same return value, same error handling) while closing the injection vector.
