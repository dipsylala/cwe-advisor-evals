## Verdict

SQL Injection confirmed. The application constructs an INSERT query via string concatenation with untrusted request header data and executes it without parameterization, allowing an attacker to inject SQL metacharacters and manipulate the query.

## Source

**File:** BenchmarkTest00018.java  
**Lines:** 54, 60

- Line 44-49: Untrusted data source - request header read via `request.getHeaders("BenchmarkTest00018")`
- Line 54: Data flows into SQL string via concatenation: `"INSERT INTO users (username, password) VALUES ('foo','" + param + "'")"`
- Line 60: Unsanitized SQL executed: `statement.executeUpdate(sql)`

Attacker-controlled input (`param`) is concatenated directly into the SQL query string. The `Statement.executeUpdate()` sink executes the malformed query as-is.

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
                    org.owasp.benchmark.helpers.DatabaseHelper.getConnection();
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql);
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

The vulnerability stems from concatenating untrusted request data into a SQL query string. An attacker can inject SQL metacharacters to alter query logic—for example, `' OR '1'='1` injected into the password field would bypass intended constraints or disclose data.

**Remediation approach:**

1. **Parameterized Query**: Replace string concatenation with a `?` placeholder (`VALUES ('foo', ?)`) to separate query structure from data
2. **PreparedStatement**: Use `PreparedStatement` instead of `Statement` to enforce separation of SQL syntax and parameters
3. **Parameter Binding**: Use `setString(1, param)` to safely bind the untrusted input to the placeholder. The database driver ensures special characters are escaped and treated as data, not executable SQL
4. **Connection Access**: Changed from `DatabaseHelper.getSqlStatement()` to `DatabaseHelper.getConnection()` to properly instantiate a prepared statement via the connection object

This fix ensures that user input cannot modify SQL query structure, eliminating SQL injection even for payloads containing quotes, semicolons, or other SQL metacharacters.
