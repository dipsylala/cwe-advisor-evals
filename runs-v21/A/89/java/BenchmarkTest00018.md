## Verdict
CONFIRMED - SQL Injection via string concatenation in dynamically constructed INSERT statement.

## Source
User input from request header `BenchmarkTest00018` (line 45-48), URL-decoded (line 52), and concatenated directly into SQL query (line 54).

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
            java.sql.Connection connection = org.owasp.benchmark.helpers.DatabaseHelper.getConnection();
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
The original code constructs a SQL INSERT statement by concatenating the unsanitized user input `param` directly into the query string (line 54). This allows an attacker to inject arbitrary SQL by crafting a malicious header value.

The fix uses a prepared statement with a parameter placeholder (`?` at line 54) and binds the user input safely using `setString()` (line 60). This separates the SQL command structure from the data, preventing SQL injection. The database driver treats the bound parameter as data only, never as executable SQL code, regardless of its content.

Key changes:
- Line 54: Use `?` placeholder instead of string concatenation
- Lines 57-60: Replace Statement with PreparedStatement, obtain a Connection, prepare the statement, bind the parameter, and execute
