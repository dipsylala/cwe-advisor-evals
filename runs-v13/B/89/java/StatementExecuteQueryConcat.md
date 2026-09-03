## Verdict
Exploitable. The untrusted `customerId` parameter from `request.getParameter("customerId")` is concatenated directly into the SQL query string without parameterization, allowing SQL injection at the sink `statement.executeQuery(sql)`.

## Source
User-controlled input:
```java
String customerId = request.getParameter("customerId");  // Line 31
```

## Fix

**Vulnerable code (lines 47–54):**
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement()) {

        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = " + customerId;
        ResultSet resultSet = statement.executeQuery(sql);
```

**Fixed code:**
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection()) {
        String sql = "SELECT id, full_name, email, account_status FROM customers WHERE id = ?";
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
```

## Explanation
The fix replaces the unsafe `Statement` with a parameterized `PreparedStatement`. The `?` placeholder in the SQL string reserves a position for the parameter value, and `setString(1, customerId)` binds the user input as data rather than query structure. This ensures the database treats `customerId` as a literal value, preventing SQL injection. The attacker's input, even if it contains SQL metacharacters like `' OR '1'='1`, cannot alter the query's logic. The `try-with-resources` statement ensures both the prepared statement and connection are properly closed.

## Behaviour changes
- Changed from `Statement` to `PreparedStatement`: The prepared statement is compiled once with the query structure fixed and parameters bound separately, providing injection protection and potential performance benefits from query plan caching.
- Moved `Statement` resource to wrap the `PreparedStatement` instead of being created at the connection level: This narrows the scope of the prepared statement resource and ensures it is closed immediately after use, improving resource management.
- The query now uses `?` placeholder syntax instead of string concatenation: The SQL string is now static and parameter positions are bound separately using `setString()`, which is the Java JDBC standard for safe parameterization.
- No functional changes to the ResultSet handling or output logic: The rest of the method remains unchanged—`executeQuery()` is called on the prepared statement (no arguments, unlike the original), and the result set is processed identically to the original code.
