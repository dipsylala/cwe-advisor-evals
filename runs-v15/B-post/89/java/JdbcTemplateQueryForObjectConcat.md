## Verdict

Exploitable. The `orderNumber` parameter flows untrusted from the HTTP request directly into a SQL string via concatenation, then into `JdbcTemplate.queryForObject()`. An attacker can inject SQL operators to bypass the WHERE clause and extract arbitrary data.

## Source

HTTP request parameter `orderNumber` (@RequestParam at line 23) flows through `OrderLookupController.lookupOrder()` to `OrderLookupService.findByOrderNumber()` (line 24).

## Fix

**Vulnerable code:**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = '" + orderNumber + "'";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER);
}
```

**Fixed code:**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = ?";
    return jdbcTemplate.queryForObject(sql, new Object[]{orderNumber}, ORDER_ROW_MAPPER);
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. The `?` placeholder marks a bind-parameter position. `orderNumber` is now passed separately as an argument (`new Object[]{orderNumber}`) to `queryForObject()`, which automatically escapes it as a data value, not SQL structure. The JDBC driver ensures special characters in `orderNumber` cannot alter the query logic. This is the only safe pattern for value positions in JDBC/Spring and eliminates SQL injection at the source.

## Behaviour changes

None. The parameterized query executes the same logical query and returns the same `Order` object. The exception contract is unchanged: `EmptyResultDataAccessException` if no row matches, `IncorrectResultSizeDataAccessException` if multiple rows match. The row mapper (`ORDER_ROW_MAPPER`) receives the same result set and produces the same object.
