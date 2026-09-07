## Verdict

VULNERABLE. Line 54 passes an unsanitized user input (`customerId`, sourced from `request.getParameter()` on line 31) into a SQL query built by string concatenation on lines 51-52, then executes it with `Statement.executeQuery()`. An attacker can inject SQL operators and clauses by supplying a value like `1 OR 1=1` or `1; DROP TABLE customers;--`.

## Source

**Entry point** (line 31): `String customerId = request.getParameter("customerId");`

**Data flow**: `customerId` parameter flows directly into SQL string concatenation (lines 51-52) without parameterization or validation, then is executed via `Statement.executeQuery(sql)` (line 54).

**Sink** (line 54): `ResultSet resultSet = statement.executeQuery(sql);` — the SQL injection taint sink where the concatenated query is executed.

## Fix

Replace the string-concatenated SQL with a `PreparedStatement` using a `?` placeholder, and bind the parameter separately:

**Vulnerable code** (lines 47-66):
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement()) {

        String sql = "SELECT id, full_name, email, account_status "
                + "FROM customers WHERE id = " + customerId;  // INJECTION: customerId concatenated directly
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

**Fixed code**:
```java
private void writeCustomerSummary(String customerId, PrintWriter writer) throws SQLException {
    try (Connection connection = dataSource.getConnection();
         PreparedStatement statement = connection.prepareStatement(
                 "SELECT id, full_name, email, account_status FROM customers WHERE id = ?")) {

        statement.setString(1, customerId);  // Bind parameter safely
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

**Changes**:
- Line 48-49: Changed `Statement statement = connection.createStatement()` to `PreparedStatement statement = connection.prepareStatement("SELECT id, full_name, email, account_status FROM customers WHERE id = ?")`. The SQL structure is now fixed, and the `?` placeholder reserves a position for a bound parameter.
- Added line 51: `statement.setString(1, customerId)` binds the user input as a typed parameter (the first `?`), ensuring it is treated as a string value, never as SQL syntax.
- Line 52: Changed `statement.executeQuery(sql)` to `statement.executeQuery()` because the SQL is now part of the prepared statement, not passed as an argument.

## Explanation

A `PreparedStatement` separates SQL structure from data. The SQL template is parsed and compiled once when `prepareStatement()` is called, establishing the query structure. The `?` placeholder reserves a fixed slot for a value. When `setString()` binds the `customerId`, the database driver treats it as literal data, not executable SQL — even if the string contains SQL syntax like `' OR '1'='1` or `; DROP TABLE;`. This is the primary defence against SQL injection.

The fix preserves the original contract: the statement still returns a `ResultSet`, still throws `SQLException` on error, and still executes the same logical query when `customerId` is a legitimate ID. The only change is that the user input can no longer modify the query structure.

The plain-text concatenation in the error message on the new line 63 (`"No customer found for id " + customerId`) is not a SQL injection risk because it writes to the response body as text, not into a query.

## Behaviour changes

- **SQL execution**: The query structure is now fixed at prepare time and cannot be modified by the parameter value. An attacker cannot inject operators, clauses, or subqueries.
- **Parameter binding**: The `customerId` value is now passed through the driver's parameterization mechanism (the JDBC type system), which ensures type safety and escaping.
- **Error handling**: No change. `PreparedStatement.executeQuery()` still throws `SQLException` on database errors and returns a `ResultSet` on success.
- **Performance**: Prepared statements can be slightly faster in high-throughput scenarios because the database driver can parse and cache the statement template; no performance regression.
- **Output**: No change. The result set iteration, row fetching, and response formatting remain identical.
