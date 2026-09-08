## Verdict

SQL injection vulnerability confirmed. Untrusted input from `request.getHeader()` is concatenated directly into a SQL string before the CallableStatement is prepared. The fix applies allowlist validation to the procedure name parameter.

## Source

- **Entry point**: `request.getHeader("BenchmarkTest00008")` (line 46)
- **URL decoding**: Line 50 (does not sanitize SQL)
- **Vulnerable concatenation**: Line 52 - `String sql = "{call " + param + "}"` directly concatenates untrusted input
- **Sink**: `connection.prepareCall(sql)` and `statement.executeQuery()` (lines 57, 59)

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
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    // Allowlist of permitted stored procedure names
    private static final Set<String> ALLOWED_PROCEDURES = new HashSet<String>() {
        {
            add("sp_GetData");
            add("sp_UpdateData");
        }
    };

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

        // Validate procedure name against allowlist
        if (!ALLOWED_PROCEDURES.contains(param)) {
            response.getWriter().println("Invalid procedure name");
            return;
        }

        String sql = "{call " + param + "}";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            // SAST FINDING FIXED: CWE-89 (SQL Injection) - procedure name is now validated against allowlist before concatenation
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

The vulnerability is that `param` (derived from an HTTP header) is concatenated directly into the SQL string before the statement is prepared. Although `CallableStatement` is used, the injection occurs at concatenation time (line 52), before parameterization is applied. 

The procedure name itself cannot be parameterized using standard `?` placeholders—the SQL dialect requires the procedure name to be part of the query structure, not a data value. Per the Java CWE guidance, dynamic identifiers must be validated against a server-side allowlist rather than accepted from user input. The fix introduces a static `Set<String>` of permitted procedure names (`ALLOWED_PROCEDURES`) and validates the incoming `param` against it before concatenation. If the value is not in the allowlist, the request is rejected. Only validated procedure names can reach the `prepareCall()` sink, eliminating the concatenation-based injection path.

## Behaviour changes

- Requests with procedure names not in the `ALLOWED_PROCEDURES` set are rejected with "Invalid procedure name" returned to the client and execution returns early.
- Requests with allowlisted procedure names proceed as before.
- The CallableStatement is now built only from the validated, server-controlled procedure name.
- No change to the method's exception handling or return value contract.
