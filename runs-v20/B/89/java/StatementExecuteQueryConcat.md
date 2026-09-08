## Verdict

exploitable

- cwe_id: CWE-89
- location: CustomerLookupServlet.java, line 54 (sink: `statement.executeQuery(sql)`)
- confidence: high

## Source

`request.getParameter("customerId")` at line 31, in `doGet`. The value is only checked for null/empty (lines 32-35) - no type or format validation - then passed unchanged into `writeCustomerSummary(customerId, writer)` (line 40), whose parameter flows directly into the SQL string built at lines 51-52.

## Fix

### File: CustomerLookupServlet.java

```java
package com.example.customers;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Looks up a single customer record by the customerId request parameter and
 * renders a small summary. Used by the account lookup page in the support
 * console.
 */
public class CustomerLookupServlet extends HttpServlet {

    private final CustomerDataSource dataSource;

    public CustomerLookupServlet(CustomerDataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String customerId = request.getParameter("customerId");
        if (customerId == null || customerId.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "customerId is required");
            return;
        }

        response.setContentType("text/plain");
        try (PrintWriter writer = response.getWriter()) {
            try {
                writeCustomerSummary(customerId, writer);
            } catch (SQLException e) {
                throw new ServletException("Failed to look up customer " + customerId, e);
            }
        }
    }

    private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = ?";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, customerId);
            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                writer.printf("Customer #%s: %s <%s> [%s]%n",
                        resultSet.getString("id"),
                        resultSet.getString("full_name"),
                        resultSet.getString("email"),
                        resultSet.getString("account_status"));
            } else {
                writer.println("No customer found for id " + customerId);
            }
        }
    }
}
```

## Explanation

The sink built its SQL by concatenating the raw `customerId` request parameter into an unquoted numeric position (`WHERE id = " + customerId`), so a value such as `1 OR 1=1` or `1; DROP TABLE customers` changes the query's logic or structure rather than supplying a value. The fix replaces the `Statement`/string-concatenation pattern with a `PreparedStatement` using a `?` placeholder for the `id` value, and binds `customerId` with `setString(1, customerId)` instead of splicing it into the SQL text. The database driver now sends the value as a separate parameter, so it can only ever be interpreted as data for the comparison, never as SQL syntax - closing the injection regardless of what characters the caller supplies. No allowlist is needed because the `?` occupies a value position, not an identifier or clause.

## Behaviour changes

- `Statement` replaced with `PreparedStatement`, and `createStatement()`/`executeQuery(sql)` replaced with `prepareStatement(sql)`/`executeQuery()` taking no argument - required to bind the placeholder; the returned `ResultSet` and all downstream row handling are unchanged.
- `customerId` is now bound via `setString(1, customerId)` rather than concatenated as unquoted text. If the `id` column is numeric, the driver converts the bound string the same way it would coerce a literal; a non-numeric `customerId` that previously caused the database to raise a syntax error (surfaced as a 500 via the wrapped `ServletException`) will instead produce no matching row, so the servlet now returns "No customer found for id ..." for that case rather than an error. This is a narrowing of behavior for malformed/malicious input only and does not affect any legitimate numeric customer ID.
- No other arguments, return values, or control flow were changed; the connection/statement try-with-resources scoping, error handling, and output format are identical to the original.

verification: `javac` (JDK 26) compiled the fixed file successfully (exit 0, no diagnostics) against minimal same-signature stubs for the external `javax.servlet.*` types and `CustomerDataSource` (no servlet-api jar or the rest of the application was available in this environment); the real project's own build should be re-run against the actual dependencies before merging.

assumptions: none - the `id` column's exact SQL type is not shown in the case file, but `setString` is safe for both a numeric and a character `id` column since the JDBC driver performs the same coercion a driver would apply to an equivalent literal.
