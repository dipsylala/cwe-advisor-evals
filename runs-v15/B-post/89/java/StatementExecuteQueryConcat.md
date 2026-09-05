## Verdict

Exploitable

## Source

User input from HTTP request parameter at line 31: `String customerId = request.getParameter("customerId");`

## Fix

### Vulnerable Code
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement()) {

        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = " + customerId;
        // SQL injection sink: untrusted customerId concatenated directly into SQL
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

### Fixed Code
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    String sql = "SELECT id, full_name, email, account_status FROM customers WHERE id = ?";
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
```

Add import: `import java.sql.PreparedStatement;`

## Explanation

The fix replaces string concatenation with a parameterized query using `PreparedStatement`. The SQL string now contains a `?` placeholder in place of the untrusted `customerId` value. The placeholder is bound to the user input via `statement.setString(1, customerId)`, which treats the value as data, not executable SQL code. This prevents an attacker from injecting SQL operators or keywords—an input like `1 OR 1=1` is now treated as a literal string to match against the `id` column rather than as additional query logic. The `PreparedStatement` is created with the static SQL template and the parameter is bound before execution, ensuring separation between query structure and data.

## Behaviour changes

None. The fix preserves the sink contract: it returns a `ResultSet` containing the query results, maintains iteration via `resultSet.next()`, and preserves exception behavior (`SQLException` is thrown on database errors). The only change beyond the injection fix is that the SQL is prepared once (before binding parameters) rather than concatenated on each call, which is a performance improvement with no functional side effects.
