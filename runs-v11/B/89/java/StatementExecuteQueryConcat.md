## Verdict

Exploitable. The `customerId` parameter from `request.getParameter()` at line 31 flows directly into SQL string concatenation at lines 51-52 without any parameterization or binding, allowing SQL injection attacks.

## Source

`request.getParameter("customerId")` at line 31 in the `doGet()` method. This untrusted HTTP request parameter is passed to `writeCustomerSummary()` without validation.

## Fix

**Vulnerable code (lines 47-66):**
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement()) {

        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = " + customerId;
        // SAST FINDING: CWE-89 - Direct concatenation of user input into SQL
        ResultSet resultSet = statement.executeQuery(sql);

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
```

**Fixed code:**
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection()) {
        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            preparedStatement.setString(1, customerId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
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

The fix replaces string concatenation with a `PreparedStatement` and parameterized query. Instead of building SQL by concatenating the `customerId` directly into the query string, a `?` placeholder marks the parameter position. The `customerId` value is then bound separately via `preparedStatement.setString(1, customerId)`, ensuring it is always treated as data, never as executable SQL. This eliminates the injection point entirely. The try-with-resources structure is adjusted to properly manage both the `PreparedStatement` and `ResultSet` lifecycles, ensuring all resources are closed correctly.

## Behaviour changes

- Replaced `Statement` with `PreparedStatement`: The connection now creates a prepared statement with a parameterized query instead of a plain statement.
- Added parameter binding: `preparedStatement.setString(1, customerId)` binds the untrusted input as a data value, not query syntax.
- Restructured try-with-resources: The `Statement` is replaced by `PreparedStatement`, and the `ResultSet` is now explicitly wrapped in its own try-with-resources to ensure proper closure.
- No functional changes to the result set processing or output: The query still returns the same columns and the data is processed identically.
- SQLException handling is unchanged: The method still throws `SQLException` in the same way.
