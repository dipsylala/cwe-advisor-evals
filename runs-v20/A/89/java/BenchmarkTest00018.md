## Verdict

Confirmed. The value taken from the `BenchmarkTest00018` request header is URL-decoded and concatenated directly into a SQL `INSERT` statement, which is then run with `Statement.executeUpdate(sql)`. An attacker who controls that header can inject arbitrary SQL (e.g. close the string literal and append additional clauses or statements).

## Source

`request.getHeaders("BenchmarkTest00018")` in `doPost` (line 45) supplies the first header value as `param`; it is URL-decoded (line 52) and concatenated into the `sql` string (line 54) with no escaping or parameterization before reaching the `Statement.executeUpdate(sql)` sink (line 60).

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
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            java.sql.PreparedStatement pstmt = statement.getConnection().prepareStatement(sql);
            pstmt.setString(1, param);
            int count = pstmt.executeUpdate();
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

The query text is now a fixed, parameterized SQL statement (`?` placeholder for the password value) rather than a string built by concatenating attacker-controlled input. The header value is bound through `PreparedStatement.setString(1, param)`, so the driver sends it as literal data and it can never change the structure of the SQL statement, regardless of quotes, `--`, `;`, or other metacharacters it contains. The `PreparedStatement` is obtained from the same connection the existing `Statement` came from (`statement.getConnection()`), so no other code path or helper needs to change. `outputUpdateComplete` still receives a `sql` string for its existing logging/output behavior, but that string is now the static parameterized query text, not attacker-influenced content.
