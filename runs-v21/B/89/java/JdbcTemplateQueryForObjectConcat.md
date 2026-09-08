## Verdict

Exploitable. The `orderNumber` parameter is untrusted user input (via `@RequestParam`) that is concatenated directly into the SQL query string, allowing SQL injection. An attacker can supply payloads like `' OR '1'='1` to manipulate the query logic.

## Source

The `orderNumber` parameter from `@RequestParam("orderNumber")` at line 23 of the OrderLookupController.lookupOrder method. This user-controlled input is passed to OrderLookupService.findByOrderNumber() without validation or parameterization.

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

The vulnerability was in the `findByOrderNumber` method, which built the SQL query by concatenating the untrusted `orderNumber` parameter directly into the WHERE clause: `"... WHERE order_number = '" + orderNumber + "'"`. This allows an attacker to inject arbitrary SQL by providing input that breaks out of the string literal context.

The fix replaces the concatenated query with a parameterized query using a `?` placeholder: `"... WHERE order_number = ?"`. The `orderNumber` is now passed as a separate parameter to `jdbcTemplate.queryForObject(sql, ORDER_ROW_MAPPER, orderNumber)`. Spring's JdbcTemplate automatically converts this to a proper `PreparedStatement`, ensuring the parameter is always treated as data, never as executable SQL code. This eliminates the injection vector while preserving the query's intended behavior.

## Behaviour changes

None. The parameterized query produces the same results as the original code for legitimate inputs. The only change is the removal of the injection vulnerability—attackers can no longer manipulate the query structure using specially crafted `orderNumber` values.
