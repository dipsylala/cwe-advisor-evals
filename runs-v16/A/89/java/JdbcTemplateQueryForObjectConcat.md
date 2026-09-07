## Verdict
SQL Injection vulnerability confirmed. User-supplied `orderNumber` is concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL.

## Source
Lines 40-43 in `OrderLookupService.java`:
```java
String sql = "SELECT id, order_number, customer_name, total_cents " +
        "FROM orders WHERE order_number = '" + orderNumber + "'";
return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER);
```

The `orderNumber` parameter flows directly from the HTTP request parameter into the SQL query via string concatenation.

## Fix
Replace string concatenation with parameterized query using `?` placeholders:

```java
Order findByOrderNumber(String orderNumber) {
    String sql = "SELECT id, order_number, customer_name, total_cents " +
            "FROM orders WHERE order_number = ?";
    return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber);
}
```

## Explanation
Parameterized queries separate the SQL command structure from the data values. The `?` placeholder is a parameter marker that JdbcTemplate replaces with a properly escaped value. The `orderNumber` is now passed as the third argument to `queryForObject()`, where it is bound as data rather than concatenated as SQL syntax. This prevents the attacker-controlled input from altering the query structure, regardless of what special characters or SQL keywords it contains.
