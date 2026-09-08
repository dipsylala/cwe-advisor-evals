## Verdict

CONFIRMED - SQL Injection vulnerability. User-supplied `customerId` parameter is concatenated directly into the SQL query string without parameterization, allowing attackers to inject arbitrary SQL.

## Source

Line 31-32: `customerId` originates from an untrusted HTTP request parameter via `request.getParameter("customerId")`.

Line 52: The `customerId` is concatenated directly into the SQL query string without any escaping or parameterization.

Line 54: The resulting query is executed via `statement.executeQuery(sql)`, allowing injected SQL to execute.

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

The vulnerability was caused by string concatenation of the user-controlled `customerId` parameter into the SQL query. This allowed attackers to inject arbitrary SQL commands.

The fix uses Java's `PreparedStatement` API, which provides parameterized query execution:

1. Import `java.sql.PreparedStatement` instead of `Statement`.
2. Change `connection.createStatement()` to `connection.prepareStatement()` with the SQL query containing a `?` placeholder.
3. Bind the user input to the placeholder using `statement.setString(1, customerId)` before execution.

This approach ensures that user input is treated as data, not as executable SQL. The database driver handles proper escaping and quoting, preventing SQL injection attacks regardless of the input content.

The fix maintains the same functionality while eliminating the injection vulnerability. Even if an attacker submits input like `1'; DROP TABLE customers; --`, it will be treated as a literal string value for the `id` column, not as SQL commands.
