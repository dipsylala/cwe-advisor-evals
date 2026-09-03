## Verdict

Exploitable. The `orderNumber` parameter from user input is directly concatenated into the SQL query string, allowing attackers to inject arbitrary SQL code (e.g., `' OR '1'='1` to bypass the WHERE clause or `'; DROP TABLE orders; --` to execute additional commands).

## Source

User input enters via the `@RequestParam("orderNumber")` annotation in the `OrderLookupController.lookupOrder()` method (line 23). The raw, untrusted parameter is passed directly to `OrderLookupService.findByOrderNumber()` without any validation or sanitization.

## Fix

Replace string concatenation with parameterized queries using `?` placeholders. Pass the parameter separately to `JdbcTemplate.queryForObject()`:

**Before:**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = '" + orderNumber + "'";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER);
}
```

**After:**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = ?";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber);
}
```

## Explanation

Parameterized queries are the standard defence against SQL injection in Java. The `?` placeholder tells the JDBC driver that `orderNumber` is data, not SQL structure. The driver handles escaping and type coercion according to the database's protocol, preventing injection attacks regardless of the input's content. Even special characters like single quotes, semicolons, or SQL keywords in `orderNumber` are now treated as literal string values within the WHERE clause, not executable SQL syntax. This fix applies the primary defence recommended in CWE-89 guidance and is the documented best practice for Spring's `JdbcTemplate`.

## Behaviour changes

None. The parameterized query is functionally identical to the vulnerable concatenated string; it returns the same result set under all legitimate inputs. The only runtime change is the mechanism by which the parameter is bound to the SQL statement — a detail internal to the JDBC driver. No changes to method signature, return type, exception handling, or query semantics occur.
