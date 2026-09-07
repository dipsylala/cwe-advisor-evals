## Verdict
CONFIRMED SQL Injection via string concatenation of user-controlled input into SQL query.

## Source
Line 52 concatenates the unsanitized `customerId` parameter directly into the SQL query string:
```
String sql = "SELECT id, full_name, email, account_status "
        + "FROM customers WHERE id = " + customerId;
```

This concatenated SQL is then executed at line 54 via `statement.executeQuery(sql)`, making it a taint sink. An attacker can inject SQL metacharacters through the `customerId` parameter to execute arbitrary queries.

## Fix
Replace string concatenation with a `PreparedStatement` to use parameterized queries:

```java
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
```

## Explanation
Parameterized queries (`PreparedStatement` with `?` placeholders) separate SQL structure from user data. The database driver treats the placeholder as a literal value, not executable SQL code, preventing injection attacks regardless of special characters in `customerId`. The `setString()` call safely binds the parameter with proper escaping at the driver level.
