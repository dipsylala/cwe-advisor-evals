## Verdict
Confirmed. `customerId` comes from an unvalidated HTTP request parameter (`request.getParameter("customerId")` in `doGet`) and is concatenated directly into a SQL string that is run with `Statement.executeQuery`, allowing SQL injection.

## Source
`request.getParameter("customerId")` in `CustomerLookupServlet.doGet` (line 31), passed unmodified into `writeCustomerSummary`.

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
            try (ResultSet resultSet = statement.executeQuery()) {
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
}
```

## Explanation
The query text is now a fixed string with a single `?` placeholder for the `id` predicate; `customerId` is bound with `PreparedStatement.setString(1, customerId)` instead of being concatenated into the SQL. The JDBC driver sends the value as data, not as part of the command, so it cannot alter the statement's structure regardless of what characters it contains, and the driver/database perform any needed type coercion from the string to the `id` column's type when comparing. `Statement` and its `executeQuery(sql)` call are removed entirely, closing the sink. The `ResultSet` is now also wrapped in try-with-resources, since a `PreparedStatement` is reused across calls in general and results should be closed explicitly; this does not change externally visible behavior. No other behavior changes: the same columns are selected, the same not-found message is written (which is safe since it's only echoing the request value back to the same client that supplied it, not part of a SQL statement), and error handling is unchanged.
