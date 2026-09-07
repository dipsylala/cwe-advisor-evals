## Verdict

Exploitable. The `orderNumber` parameter flows directly from `@RequestParam` at line 23, through string concatenation at line 41, into the SQL query executed at line 43 via `JdbcTemplate.queryForObject()` without parameterization. An attacker can inject SQL operators to bypass the WHERE clause (e.g., `' OR '1'='1`) and access unauthorized records.

## Source

`@RequestParam("orderNumber")` in `OrderLookupController.lookupOrder()` at line 23 receives untrusted HTTP request data and passes it to `OrderLookupService.findByOrderNumber()` at line 24.

## Fix

**Vulnerable code (line 40-43):**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = '" + orderNumber + "'";
    // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER);
}
```

**Fixed code:**
```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = ?";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber);
}
```

**Library recommendation:** None. Spring JdbcTemplate is already a dependency in the codebase. No version change required.

## Explanation

The fix replaces string concatenation with a parameterized query using a `?` placeholder. The `orderNumber` is now passed as a separate parameter to `queryForObject()` rather than being embedded in the SQL string. Spring's `JdbcTemplate` treats the parameter as data only—the value cannot be interpreted as SQL syntax, operators, or comments. This eliminates the injection vector while maintaining the same behavior: the query still filters by `order_number` and returns an `Order` object via the `RowMapper`.

## Behaviour changes

None. The fixed code preserves the original method's contract: it accepts the same parameter type (`String`), executes the same logical query (SELECT with WHERE clause), and returns the same type (`Order`). JdbcTemplate's parameterization is transparent to the caller and does not alter the return value, error handling, or result set processing via `ORDER_ROW_MAPPER`.
