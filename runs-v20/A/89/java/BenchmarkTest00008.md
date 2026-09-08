## Verdict

Confirmed. `doPost` reads the `BenchmarkTest00008` HTTP header, URL-decodes it, and concatenates the raw result directly into the text of a SQL call statement (`"{call " + param + "}"`). The entire statement text -- not just a value inside it -- is attacker-controlled, and it is executed via `CallableStatement.executeQuery()` with no validation or parameterization. This is a textbook CWE-89 SQL Injection sink.

## Source

- `HttpServletRequest.getHeader("BenchmarkTest00008")` in `doPost` (line 45-46) is the tainted source.
- The value flows unmodified except for `URLDecoder.decode` (line 50, which does not neutralize SQL metacharacters) into the `sql` string built at line 52, which reaches `statement.executeQuery()` at line 59.

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

        String sql = "SELECT * FROM USERS WHERE USERNAME = ?";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, param);
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

The vulnerable code let the attacker supply the entire body of the SQL call statement, so no denylist or escaping applied to `param` could close the hole -- any character sequence, including a full second statement or arbitrary procedure invocation, was accepted verbatim as SQL grammar.

The fix removes attacker input from the SQL grammar entirely. `param` is now bound through `PreparedStatement.setString(1, param)` as a data value against a fixed, literal query (`SELECT * FROM USERS WHERE USERNAME = ?`); the JDBC driver sends it to the database as parameter data, not as part of the parsed statement, so it cannot alter the query's structure regardless of its content (quotes, semicolons, comment sequences, etc. are all treated as literal characters of the search value). The dynamic `CallableStatement`/`{call ...}` construction, which required embedding untrusted text directly into call syntax, is replaced because a bind placeholder cannot stand in for an entire statement or procedure name -- only for a value -- so the safe equivalent is a parameterized lookup query using the header value as the searched value, preserving the original intent of using the header input to look up a record. `DatabaseHelper.printResults` still receives the (now static) `sql` string purely for display/logging, which carries no injected content.
