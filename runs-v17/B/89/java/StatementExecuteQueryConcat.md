## Verdict

CONFIRMED - SQL Injection vulnerability. The `customerId` parameter from the HTTP request is directly concatenated into the SQL query string without parameterization, allowing an attacker to inject SQL metacharacters and manipulate query logic.

## Source

`request.getParameter("customerId")` at line 31, passed through to `writeCustomerSummary()` where it is concatenated into SQL at line 52.

## Fix

Replace `Statement` with `PreparedStatement` and use parameterized query with `?` placeholder. Bind the untrusted parameter using `setString()` so the input is always treated as data, never as executable SQL.

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
            try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                preparedStatement.setString(1, customerId);
                ResultSet resultSet = preparedStatement.executeQuery();

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

The vulnerability is eliminated by replacing direct string concatenation with a parameterized query. The original code built the SQL string by concatenating `customerId` directly: `"... WHERE id = " + customerId`. An attacker could inject SQL syntax—for example, `1 OR 1=1` would make the query return all customers, or `1; DROP TABLE customers; --` could attempt destructive operations.

The fix uses `PreparedStatement` with a `?` placeholder that separates SQL structure from data. The `setString(1, customerId)` call binds the untrusted input as a parameter value, ensuring the database driver treats it as literal data, not executable SQL. The null/empty check at request entry remains in place as a secondary validation layer.

## Behaviour changes

None. The fix preserves the exact query semantics and output. The parameterized query executes the same SELECT statement with the same parameter binding; only the injection vector is eliminated.
