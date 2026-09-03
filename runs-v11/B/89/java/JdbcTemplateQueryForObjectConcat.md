# CWE-89 Remediation: JdbcTemplateQueryForObjectConcat

## Verdict

Exploitable. The method constructs SQL by concatenating the untrusted `orderNumber` parameter directly into the query string without parameterization, allowing an attacker to inject arbitrary SQL (e.g., `' OR '1'='1` to bypass the WHERE clause and return unauthorized records).

## Source

Entry point: `@RequestParam("orderNumber")` at line 23 in `OrderLookupController.lookupOrder()`.

Data flows from the request parameter through `OrderLookupService.findByOrderNumber(String orderNumber)` to line 40-41, where it is concatenated into an SQL query string.

## Fix

**Vulnerable code (lines 39-44):**
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

## Explanation

The fix replaces string concatenation with a parameterized query. The `?` placeholder in the SQL string is a marker for a parameter position. By passing `orderNumber` as a separate argument to `queryForObject()`, the JdbcTemplate driver treats it as data, not executable SQL. The database engine receives the query structure and the value separately, making injection impossible—any special characters in `orderNumber` (such as quotes or SQL keywords) are escaped automatically by the driver and have no effect on the query logic.

## Behaviour changes

None. The parameterized query executes the same logic as the original: retrieve an Order row where the order_number column matches the supplied value. The method signature, return type, and result set mapping remain identical. The fix is functionally transparent and produces no output differences when used correctly.
