## Verdict
SQL injection vulnerability confirmed at line 43. The SQL query is constructed by concatenating unsanitized user input (`orderNumber`) directly into the query string, allowing attackers to inject arbitrary SQL commands.

## Source
Lines 40-41 construct the SQL query using string concatenation with the `orderNumber` parameter received from a web request (line 23). An attacker can provide a malicious `orderNumber` value like `' OR '1'='1` to alter the query logic or extract unauthorized data.

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
The fix replaces string concatenation with parameterized query binding. Line 40-41 now uses a `?` placeholder instead of directly embedding the `orderNumber` variable into the SQL string. The `orderNumber` parameter is passed separately to `queryForObject()` as a varargs argument after the `RowMapper`, which instructs JdbcTemplate to bind it safely using a prepared statement. This separates the SQL structure from the data, preventing the user input from being interpreted as SQL code.
