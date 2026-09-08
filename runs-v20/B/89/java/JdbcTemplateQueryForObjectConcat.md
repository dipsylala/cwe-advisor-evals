## Verdict

exploitable

- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))
- **Location:** `OrderLookupService.java`, line 43 (`jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER)`)
- **Confidence:** high

## Source

`orderNumber`, the `@RequestParam("orderNumber") String orderNumber` parameter of `OrderLookupController.lookupOrder()` (line 23). It flows unmodified as an argument into `OrderLookupService.findByOrderNumber(String orderNumber)` (line 24), where it is concatenated directly into a SQL string literal at lines 40-41 with no validation or escaping in between, and that string is passed to the sink at line 43.

## Fix

### File: OrderLookupService.java

```java
package com.example.orders;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
class OrderLookupController {

    private final OrderLookupService orderLookupService;

    OrderLookupController(OrderLookupService orderLookupService) {
        this.orderLookupService = orderLookupService;
    }

    @GetMapping("/orders/lookup")
    Order lookupOrder(@RequestParam("orderNumber") String orderNumber) {
        return orderLookupService.findByOrderNumber(orderNumber);
    }
}

@Service
class OrderLookupService {

    private static final RowMapper<Order> ORDER_ROW_MAPPER = OrderLookupService::mapRow;

    private final JdbcTemplate jdbcTemplate;

    OrderLookupService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    Order findByOrderNumber(String orderNumber) {
        String sql = "SELECT id, order_number, customer_name, total_cents " +
                "FROM orders WHERE order_number = ?";
        return jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber);
    }

    private static Order mapRow(ResultSet rs, int rowNum) throws SQLException {
        Order order = new Order();
        order.setId(rs.getLong("id"));
        order.setOrderNumber(rs.getString("order_number"));
        order.setCustomerName(rs.getString("customer_name"));
        order.setTotalCents(rs.getLong("total_cents"));
        return order;
    }
}

class Order {
    private long id;
    private String orderNumber;
    private String customerName;
    private long totalCents;

    long getId() {
        return id;
    }

    void setId(long id) {
        this.id = id;
    }

    String getOrderNumber() {
        return orderNumber;
    }

    void setOrderNumber(String orderNumber) {
        this.orderNumber = orderNumber;
    }

    String getCustomerName() {
        return customerName;
    }

    void setCustomerName(String customerName) {
        this.customerName = customerName;
    }

    long getTotalCents() {
        return totalCents;
    }

    void setTotalCents(long totalCents) {
        this.totalCents = totalCents;
    }
}
```

## Explanation

The vulnerable code built the SQL statement by concatenating the raw `orderNumber` request parameter inside a quoted string literal (`... WHERE order_number = '" + orderNumber + "'"`), so any single quote or SQL metacharacter in the input alters the query's structure (e.g. `' OR '1'='1`). The fix replaces the literal with a `?` placeholder and uses `JdbcTemplate`'s `queryForObject(String sql, RowMapper<T> rowMapper, Object... args)` overload to bind `orderNumber` as a separate parameter. `JdbcTemplate` compiles the SQL text once via a `PreparedStatement` and sends the bound value out-of-band through `setObject()`, so it is always treated as a single data value for the `order_number` column and can no longer change the query's structure, regardless of its content.

## Behaviour changes

None. The sink is still `JdbcTemplate.queryForObject` with the same `ORDER_ROW_MAPPER`, so the return type, the "exactly one row" contract, and the failure behaviour are unchanged: zero matching rows still throws `EmptyResultDataAccessException` and more than one matching row still throws `IncorrectResultSizeDataAccessException`, exactly as before. The only edit is moving `orderNumber` from the SQL string into a bound `?` parameter (one placeholder added, one vararg argument added) - no arguments, defaults, or discarded output were changed.

**Verification:** `javac` (JDK 26) was run against the fixed file in isolation. No Spring dependency is available in this environment, so `javac` reported "cannot find symbol" / "package does not exist" for every Spring type (`JdbcTemplate`, `RowMapper`, `@RestController`, etc.) - the same errors the unmodified original file would also produce standalone - and no other error. No syntax or parse errors were reported, confirming the edit is syntactically valid Java. The `queryForObject(String, RowMapper<T>, Object...)` overload used is a longstanding, documented method on Spring's `JdbcTemplate` class, already the class in use in the original code; only the varargs parameter is newly introduced, matching one `?` placeholder to one bound argument.
