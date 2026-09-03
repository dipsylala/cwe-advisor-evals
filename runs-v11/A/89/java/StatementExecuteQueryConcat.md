## Verdict

Real SQL injection vulnerability. The `customerId` parameter from the HTTP request is concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

File: `evals/cases/89/java/StatementExecuteQueryConcat/CustomerLookupServlet.java`, lines 51–54

```java
String sql = "SELECT id, full_name, email, account_status "
        + "FROM customers WHERE id = " + customerId;
// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
ResultSet resultSet = statement.executeQuery(sql);
```

## Fix

Replace `Statement` with `PreparedStatement` and use parameter placeholders to separate the SQL structure from user input:

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

SQL injection occurs because the query string is built by concatenating user-supplied input directly into SQL syntax. An attacker can inject metacharacters (quotes, semicolons, SQL keywords) to alter the query structure—for example, `customerId = "1' OR '1'='1"` would turn the query into `WHERE id = 1' OR '1'='1'`, matching every row.

`PreparedStatement` fixes this by separating the SQL command structure from the data. The driver sends the query template (`?` placeholders) and data values separately to the database; the database parses the template first and then binds the data as literal values only, with no opportunity to inject SQL syntax. The `setString()` call properly escapes the customerId for its database and encoding, preventing injection.

Imports added: `java.sql.PreparedStatement` (replace the existing `Statement` import).
