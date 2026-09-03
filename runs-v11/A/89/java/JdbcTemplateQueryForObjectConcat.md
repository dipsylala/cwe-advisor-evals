## Verdict
Confirmed SQL injection vulnerability. User-supplied input from the `orderNumber` parameter is directly concatenated into the SQL query string without parameterization, allowing attackers to inject arbitrary SQL.

## Source
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = '" + orderNumber + "'";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER);
}
```

Lines 40-41 construct the query via string concatenation. Line 43 executes the vulnerable query. An attacker can provide input like `' OR '1'='1` to manipulate the query logic.

## Fix
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = ?";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber);
}
```

Replace string concatenation with parameterized query syntax. Use `?` as a placeholder in the SQL string and pass `orderNumber` as a separate argument to `queryForObject()`. JdbcTemplate handles proper escaping and parameter binding.

## Explanation
SQL injection occurs when untrusted user input is embedded directly into SQL query strings. String concatenation allows attackers to craft input that alters query logic, bypasses authentication, or accesses unauthorized data.

Parameterized queries (prepared statements) are the primary defence. The query structure is fixed at compile time, and user input is treated strictly as data values, never as SQL syntax. JdbcTemplate's `queryForObject(sql, rowMapper, parameters...)` method binds parameters safely—the database driver handles all necessary escaping.

This approach is framework-native, requires no additional libraries, and is consistent with Spring's recommended practice for SQL query execution. It eliminates the vulnerability entirely rather than attempting to sanitize input.
