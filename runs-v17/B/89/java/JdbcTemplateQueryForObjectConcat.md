## Verdict

VULNERABLE. Attacker-controlled input is concatenated directly into the SQL string without parameterization. An SQL injection attack is possible at line 43 via the `orderNumber` parameter.

## Source

HTTP request parameter `orderNumber` at line 23 (`@RequestParam("orderNumber") String orderNumber`), received by the controller and passed to `OrderLookupService.findByOrderNumber()`.

## Fix

Replace string concatenation with parameterized query using `?` placeholders:

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

The fix converts the vulnerable string concatenation to a parameterized query using Spring's `JdbcTemplate` built-in parameter binding. The SQL string now uses `?` as a placeholder for the value position (line 41), and `orderNumber` is passed as a separate varargs argument to `queryForObject()` (line 42). 

This ensures the JDBC driver treats `orderNumber` as data only, not as executable SQL code. SQL metacharacters like `'`, `--`, or `OR` in the input are safely escaped and have no effect on query structure. The parameterization prevents injection attacks while maintaining the same functionality and return contract as the original code.

The `JdbcTemplate.queryForObject(String sql, RowMapper<T> rowMapper, Object... args)` method signature accepts the SQL string with placeholders, the RowMapper for result mapping, and the parameter values in order. This is the standard Spring JDBC pattern for safe SQL execution.

## Behaviour changes

**None.** The query logic and result mapping remain identical. The parameter binding is transparent to the application logic. The fix only affects how the JDBC driver processes the query internally, preventing injection while preserving all existing behavior.

