## Verdict

Exploitable. CWE-89 (SQL Injection).

- **Location**: `BenchmarkTest00018.java`, line 60 (`statement.executeUpdate(sql)`)
- **Source**: `request.getHeaders("BenchmarkTest00018")` - the first value of a caller-controlled HTTP header, URL-decoded at line 52
- **Sink**: `java.sql.Statement.executeUpdate(String)` at line 60, executing a SQL string built by directly concatenating the decoded header value into an `INSERT` statement (line 54)
- **Confidence**: high

## Source

`request.getHeaders("BenchmarkTest00018")` (line 45) - the first element of this header's values is taken unmodified (line 48), then URL-decoded (line 52) and assigned to `param`. Nothing between the source and the sink validates, allowlists, or bounds this value; it flows straight into string concatenation.

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
        // Kept for the confirmation message only - never executed, so the literal value here is not a SQL injection sink.
        String sqlMessage = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";

        try {
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            java.sql.Connection connection = statement.getConnection();
            try (java.sql.PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                preparedStatement.setString(1, param);
                int count = preparedStatement.executeUpdate();
                org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sqlMessage, response);
            }
        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    }
}
```

## Explanation

The `INSERT` statement was built by concatenating the URL-decoded header value directly into the SQL text and executing it with `Statement.executeUpdate()`, so any quote or SQL metacharacter in the header value changes the query's structure. The fix keeps the existing `DatabaseHelper.getSqlStatement()` call (so the same connection/statement setup path still runs), retrieves the underlying `java.sql.Connection` via the standard `Statement.getConnection()` method, and opens a `PreparedStatement` from it using a static query with a single `?` placeholder in the values position. The untrusted value is then bound with `setString(1, param)` instead of being spliced into the SQL text, so the driver always treats it as a literal data value regardless of its content, which closes the injection. The `PreparedStatement` is opened in a try-with-resources block so it is closed after use.

## Behaviour changes

- **New resource opened per request**: a `PreparedStatement` is created from the connection returned by `statement.getConnection()` and closed via try-with-resources at the end of the block. Reason: required to bind the parameter instead of concatenating it. The original `Statement` object from `DatabaseHelper.getSqlStatement()` is still obtained (preserving whatever setup/pooling behaviour that call performs) but is no longer the object that executes the query; it is left unclosed exactly as in the original code, so no new resource leak is introduced.
- **Confirmation message text unchanged**: `outputUpdateComplete()` still receives a string containing the literal (concatenated) value, via a new `sqlMessage` variable, so the HTTP response confirmation text is byte-for-byte the same as before. This variable is never executed as SQL, only passed to the output helper, so it does not reintroduce the injection.
- **`sql` now contains a placeholder (`?`) instead of the literal value**: this is the query actually sent to the database and is the mechanism of the fix, not an incidental change.
- Return value (`count`), exception handling, response content type, and control flow are all unchanged.

**Verification**: No Java compiler/build was reachable for this file in isolation - it depends on `javax.servlet` (Servlet API) and `org.owasp.benchmark.helpers.DatabaseHelper`, neither of which is present in the case directory or this environment, so `javac` would fail on unresolved symbols unrelated to the fix rather than validate it. Verified by manual review instead: `java.sql.Statement.getConnection()`, `java.sql.Connection.prepareStatement(String)`, and `java.sql.PreparedStatement.setString(int, String)` are all standard `java.sql` API methods with signatures matching their usage here; `PreparedStatement` extends `AutoCloseable` via `Statement`, so the try-with-resources block is valid syntax; every other identifier (`DatabaseHelper.getSqlStatement()`, `DatabaseHelper.outputUpdateComplete()`, `DatabaseHelper.hideSQLErrors`) is unchanged from the original file and was already in use there. No new third-party or project-internal names were introduced.

Assumption: `java.sql.Statement.getConnection()` returns the same `Connection` instance that `DatabaseHelper.getSqlStatement()` used internally to create the statement, per the JDBC `Statement` interface contract; this avoids depending on any unverified `DatabaseHelper` method for obtaining a connection directly.
