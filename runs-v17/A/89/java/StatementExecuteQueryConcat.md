## Verdict
Real issue confirmed. CWE-89 SQL injection via string concatenation of untrusted request parameter into SQL query.

## Source
Line 51-54: HTTP request parameter `customerId` is concatenated directly into SQL query string without parameterization, then executed via `statement.executeQuery(sql)`.

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
        try (Connection connection = dataSource.getConnection()) {
            String sql = "SELECT id, full_name, email, account_status "
                    + "FROM customers WHERE id = ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
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
}
```

## Explanation
Replace `Statement` with `PreparedStatement`. Change the SQL query to use a `?` placeholder instead of string concatenation, then bind the parameter using `setString()`. This separates SQL structure from data, preventing attacker control over the query syntax. The database driver handles escaping and quoting, ensuring the value is treated as data, not executable SQL.
