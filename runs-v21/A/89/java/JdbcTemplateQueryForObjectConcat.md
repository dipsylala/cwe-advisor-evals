## Verdict

The vulnerability is real. The code constructs an SQL query using string concatenation of user-supplied input without any parameterization, allowing SQL injection attacks.

## Source

Lines 40-43 in `OrderLookupService.java` construct the SQL query by concatenating the `orderNumber` parameter directly into the SQL string, then pass it to `JdbcTemplate.queryForObject()`. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) through the `orderNumber` request parameter to alter query logic or extract unauthorized data.

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

The fix replaces string concatenation with parameterized query syntax:

1. **SQL Statement**: Replace the concatenated string with a placeholder: `"... WHERE order_number = ?"` instead of `"... WHERE order_number = '" + orderNumber + "'"`

2. **Parameter Binding**: Pass the user-supplied value as a separate argument to `JdbcTemplate.queryForObject()`: `jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber)`

When JdbcTemplate uses parameterized queries, it separates the SQL structure from the data values. The database driver ensures that `orderNumber` is always treated as a literal value, not as executable SQL code, regardless of what characters it contains. This makes SQL injection impossible because the query structure cannot be altered by the parameter value.
