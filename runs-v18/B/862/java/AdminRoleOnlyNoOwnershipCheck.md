## Verdict

CONFIRMED. The `OrderService.updateOrder()` method performs a sensitive operation (updating an order) without verifying that the authenticated user owns the order being modified. The vulnerability exists at line 24 where `orderRepository.save(order)` is called. Any authenticated user with the USER role can update any order by changing the orderId in the URL.

## Source

The source of the vulnerability is the `orderId` parameter passed to `OrderService.updateOrder()`. This parameter is user-controlled (from the URL path) and is used directly to fetch and update an order without ownership verification.

The vulnerable code path:
1. Controller receives `orderId` from URL path parameter
2. Service method calls `orderRepository.findById(orderId)` - fetches ANY order with that ID
3. Service updates shipping address and status
4. Service saves the order - no ownership check has occurred

## Fix

### File: OrderService.java

```java
package com.example.orders;

import org.springframework.stereotype.Service;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.NoSuchElementException;

@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        
        Order order = orderRepository.findByIdAndCustomerUsername(orderId, currentUsername)
                .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }
}
```

### File: OrderRepository.java

```java
package com.example.orders;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OrderRepository extends JpaRepository<Order, Long> {
    Optional<Order> findByIdAndCustomerUsername(Long id, String customerUsername);
}
```

## Explanation

The fix adds a resource-level ownership check to the service method by modifying how the order is fetched from the database. Instead of unconditionally loading any order with `findById(orderId)`, the fixed code uses a scoped repository query `findByIdAndCustomerUsername(orderId, currentUsername)` that only returns orders owned by the authenticated user.

The authenticated user's username is extracted from the SecurityContextHolder (Spring's standard mechanism for accessing authentication details in the current thread). The scoped query combines both the order ID and the owner's username, ensuring the lookup fails (returns empty) if either the order doesn't exist OR the user doesn't own it. Both cases throw the same NoSuchElementException with an identical message, preventing attackers from distinguishing between "order doesn't exist" and "you don't own this order" - this maps to a 404 response in the HTTP layer and prevents enumeration attacks.

The `@PreAuthorize("hasRole('USER')")` annotation on the controller method remains sufficient at the role level; the service-layer ownership check provides the required resource-level authorization gate. This follows the guidance: "Check both the action (does the caller hold the required role or permission) and the resource (does the caller own or have a granted relationship to this specific record)."

## Behaviour changes

**Before**: Any authenticated user holding the USER role can update any order in the system by manipulating the orderId URL parameter.

**After**: An authenticated user can only update orders they own (orders where the `customerUsername` field matches their authenticated username). Attempts to update orders owned by other users result in a 404 (NoSuchElementException), identical to the response for non-existent orders.

**Test verification**: Call the `/api/orders/{orderId}` endpoint as user A with an order owned by user B; the response should be 404. Call the same endpoint as user A with an order owned by user A; the response should be 200 with the updated order.
