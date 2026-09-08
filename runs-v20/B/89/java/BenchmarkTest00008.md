## Verdict

Confirmed - CWE-89 SQL Injection. Exploitable as reported.

## Source

`request.getHeader("BenchmarkTest00008")` (line 45-46), URL-decoded via `java.net.URLDecoder.decode()` (line 50) and assigned to `param`. Decoding does not neutralize SQL metacharacters, so `param` remains fully attacker-controlled.

## Fix

Assumption: the header value is meant to select which of a small, known set of stored-procedure calls to run (a common OWASP Benchmark pattern), not to supply arbitrary SQL text. No fixed set of legitimate calls is defined in the surrounding code, so the fix introduces a minimal allowlist map (`getValues` -> `{call getValues()}`) as a placeholder for the application's real set of permitted calls; the developer should replace its contents with the actual supported operations.

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

    // Fixed, developer-controlled set of permitted stored procedure calls. The header value
    // selects an entry by key; the SQL that reaches the database always comes from this map,
    // never from the request, so it cannot carry injected SQL structure.
    private static final java.util.Map<String, String> ALLOWED_CALLS;

    static {
        java.util.Map<String, String> calls = new java.util.HashMap<>();
        calls.put("getValues", "{call getValues()}");
        ALLOWED_CALLS = java.util.Collections.unmodifiableMap(calls);
    }

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

        // The request selects which permitted call to run; look it up in the allowlist instead
        // of using the raw value to build the call text.
        String sql = ALLOWED_CALLS.get(param);
        if (sql == null) {
            response.getWriter().println("Error processing request.");
            return;
        }

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

The original code built the entire JDBC call-escape string (`"{call " + param + "}"`) from the decoded header value, so the attacker controlled the full SQL text passed to `CallableStatement.prepareCall()` - not just a bound value but the call structure itself, which a `?` placeholder cannot express (placeholders bind values, not statement structure). The fix replaces the raw value with a lookup into a fixed, server-side map of permitted call strings (`ALLOWED_CALLS`): the header value is used only as a key to select one of a small number of developer-defined, parameter-free SQL statements, and the text that actually reaches `prepareCall()` always comes from that map, never from the request. A value not present in the map is rejected before any database call is made. This preserves the sink's existing contract - it still returns a `ResultSet` consumed by `DatabaseHelper.printResults()`, and the `SQLException` handling (including the `hideSQLErrors` branch and the `ServletException` rethrow) is unchanged - while eliminating the injection: an attacker can no longer influence the SQL text, only choose among the operations the application explicitly permits.

## Behaviour changes

- Previously any header value produced a `{call <value>}` attempt against the database (succeeding or failing depending on driver/DB behavior). Now only header values matching an allowlisted key (currently just `getValues`) execute a call; every other value short-circuits to the same generic `"Error processing request."` response already used for the `hideSQLErrors` case, without reaching the database.
- The allowlist's single entry (`getValues` -> `{call getValues()}`) is a placeholder standing in for whatever fixed set of stored-procedure calls the application actually needs to expose through this endpoint; it must be populated with the real supported operations before deployment.
- Checked with `javac` (JDK 26) against stub definitions of the servlet API and `DatabaseHelper` (which are not present in the case directory) - the fixed file compiles cleanly with no errors or warnings.
