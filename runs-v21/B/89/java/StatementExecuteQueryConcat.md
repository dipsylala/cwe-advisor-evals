## Verdict

Exploitable. The user-controlled `customerId` parameter from the HTTP request is directly concatenated into a SQL query string without parameterization, allowing SQL injection attacks.

## Source

Line 31: `String customerId = request.getParameter("customerId");` - untrusted HTTP request parameter.

Data flows to line 40: `writeCustomerSummary(customerId, writer)` call.

## Fix

Replace the `Statement` with a `PreparedStatement` using parameterized queries with `?` placeholders. Bind the untrusted input via `setString()` instead of concatenating it into the SQL string.

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
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT id, full_name, email, account_status FROM customers WHERE id = ?")) {

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

The vulnerability arose from building the SQL query by concatenating the untrusted `customerId` parameter directly into the query string (line 52 of the original). An attacker could inject SQL syntax such as `' OR '1'='1` to alter query logic and bypass the intended WHERE clause.

The fix replaces `Statement.createStatement()` with `connection.prepareStatement()`, which accepts a SQL template with `?` placeholders for parameterized binding. The `customerId` is no longer part of the SQL syntax; it is bound separately via `statement.setString(1, customerId)`, ensuring the database driver treats it as data, not executable SQL. This is the standard, language-agnostic SQL injection defence recommended by OWASP and MITRE.

## Behaviour changes

- Import changed from `java.sql.Statement` to `java.sql.PreparedStatement` (required by the fix).
- The SQL query is now built once at prepare time with a `?` placeholder instead of building a new string each call.
- `statement.setString(1, customerId)` binds the parameter before execution, replacing the string concatenation.
- `statement.executeQuery()` is called without a SQL argument (the SQL is already bound in the PreparedStatement).

None of these changes alter the intended behavior: the query still returns the same result set, which the code processes identically. The `ResultSet` contract is unchanged.
