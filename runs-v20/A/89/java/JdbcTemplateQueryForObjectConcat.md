## Verdict

Confirmed. `OrderLookupService.findByOrderNumber` builds the SQL statement by directly concatenating the caller-supplied `orderNumber` into a single-quoted string literal, then executes it with `JdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER)`. Any value containing a `'` (or other SQL metacharacters) breaks out of the intended literal and is interpreted as SQL, giving full SQL injection on the `orders` table.

## Source

`orderNumber` originates from the HTTP request parameter `orderNumber` on `GET /orders/lookup`, bound in `OrderLookupController.lookupOrder(@RequestParam("orderNumber") String orderNumber)`, and is passed unmodified into `OrderLookupService.findByOrderNumber(orderNumber)`.

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

The fix replaces the string-concatenated literal with a parameterized query: the SQL text now contains a `?` placeholder instead of the interpolated value, and `orderNumber` is passed as a bind argument to `JdbcTemplate.queryForObject(sql, rowMapper, args...)`. `JdbcTemplate` compiles this into a `PreparedStatement` and sends the value out-of-band from the SQL text via `setString`/`setObject`, so the driver binds it as data for the `order_number` column regardless of what characters it contains - a `'`, `--`, or any other SQL metacharacter can no longer alter the statement's structure. This is the standard, minimal fix for this class of finding: no other code path or defense mechanism is involved, the query's shape and return type are unchanged, and no library, validation, or allowlist is required.
