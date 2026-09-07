## Verdict

Exploitable. User-controlled HTTP header input is concatenated into a SQL procedure call without validation or parameterization, allowing attackers to inject arbitrary SQL commands.

## Source

**Source (untrusted input):** Line 46, `request.getHeader("BenchmarkTest00008")`

**Intermediate transformations:** Line 50, `java.net.URLDecoder.decode(param, "UTF-8")` (does not prevent SQL injection)

**Sink (execution):** Lines 52-59
- Line 52: `String sql = "{call " + param + "}"` - SQL statement built by string concatenation
- Line 57: `connection.prepareCall(sql)` - pre-built concatenated string passed to CallableStatement
- Line 59: `statement.executeQuery()` - untrusted input executed as SQL

**Data flow:** The unsanitized `param` value flows directly into the SQL call string without any allowlist validation, enabling SQL injection attacks.

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
import java.util.Arrays;
import java.util.Collections;
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

    private static final Set<String> PERMITTED_PROCEDURES =
        Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                "benchmark_proc",
                "test_procedure",
                "data_retrieval"
            ))
        );

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

        // Validate against allowlist of permitted procedure names
        if (!PERMITTED_PROCEDURES.contains(param)) {
            throw new ServletException("Invalid procedure name");
        }

        String sql = "{call " + param + "}";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
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

The vulnerability was that user input from an HTTP header was directly concatenated into a SQL procedure call string without any validation. While `CallableStatement` provides protection against SQL injection when using parameterized queries with `?` placeholders, the vulnerable code concatenated the user input into the SQL string *before* passing it to `prepareCall()`, making the injection occur at string construction time rather than at execution time.

The fix introduces an allowlist (PERMITTED_PROCEDURES) containing the set of procedure names the application is allowed to call. Before using the user-supplied parameter, the code validates that it matches one of the allowlisted names. If the input does not match any permitted procedure, a ServletException is thrown. Only after this validation passes is the parameter incorporated into the SQL string. This approach treats the input as a key into a server-controlled map of permitted values, preventing attackers from injecting arbitrary SQL code while still allowing the application to call the necessary stored procedures with dynamic procedure selection.

## Behaviour changes

**Import additions:** Added `java.util.Arrays`, `java.util.Collections`, `java.util.HashSet`, and `java.util.Set` to support the allowlist implementation. These are standard Java library classes with no external dependencies.

**Class constant addition:** Added `PERMITTED_PROCEDURES` static final field containing an unmodifiable Set of permitted procedure names. This establishes the server-controlled set of valid procedures.

**Validation check addition:** Added an allowlist validation check (lines 65-68) that throws a `ServletException` if the user input does not match a permitted procedure name. This is a new control flow that rejects invalid inputs before they reach the sink.

**No sink contract changes:** The `CallableStatement.prepareCall()` method still receives a string built from user input (but now validated), and `statement.executeQuery()` still executes that call. The fix preserves the existing behavior for valid procedure names while blocking invalid ones.

**Removed SAST comment:** Removed the inline SAST tool comment that marked the finding (was on original line 58). This is a test artifact cleanup.

**Sink contract preservation:** The fix does not alter what `executeQuery()` returns, how errors are handled, or any other aspect of the sink's contract—it only constrains what values can reach the sink to a server-controlled allowlist.
