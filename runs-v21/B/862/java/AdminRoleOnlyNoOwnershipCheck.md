## Verdict

The finding is confirmed. The `updateOrder()` method at line 24 of OrderService performs a sensitive database operation (persisting order modifications) without verifying the caller owns the order being modified. The controller method guards the endpoint with a role check (`@PreAuthorize("hasRole('USER')")`), but this gate checks only that the caller is authenticated—any logged-in user can modify any order by changing the orderId in the URL. The authorization check is entirely absent at the service layer.

## Source

The call path originates in the REST controller:

```
OrderController.updateOrder(orderId, request)
  → checks: hasRole('USER')  [authentication only, not authorization]
  ↓
OrderService.updateOrder(orderId, request)
  → performs: orderRepository.findById(orderId)  [no ownership check]
  → modifies: order.setShippingAddress(), order.setStatus()
  → persists: orderRepository.save(order)  [line 24 - sink]
  ↓
Result: Any logged-in user can modify any order
```

The Order entity carries a `customerUsername` field that stores the owner. This field is never consulted before the save operation.

## Fix

Two files must be modified:

### File: OrderService.java

```java
package com.example.orders;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @PreAuthorize("@orderSecurity.isOwner(#orderId, authentication.name)")
    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }
}
```

### File: OrderSecurity.java

```java
package com.example.orders;

import org.springframework.stereotype.Component;
import java.util.Optional;

@Component
public class OrderSecurity {

    private final OrderRepository orderRepository;

    public OrderSecurity(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public boolean isOwner(Long orderId, String username) {
        Optional<Order> order = orderRepository.findById(orderId);
        return order.isPresent() && order.get().getCustomerUsername() != null
                && order.get().getCustomerUsername().equals(username);
    }
}
```

## Explanation

The fix adds an ownership gate at the service layer through Spring Security's method-level authorization. The `@PreAuthorize("@orderSecurity.isOwner(#orderId, authentication.name)")` annotation on `updateOrder()` intercepts every call and delegates to the `OrderSecurity` bean's `isOwner()` method, passing the orderId path parameter and the authenticated caller's name. The bean loads the order from the repository and verifies that the order's `customerUsername` matches the caller's identity. If ownership is not confirmed, Spring Security raises `AccessDeniedException`, which the framework translates into a 403 response for authenticated callers. The bean name defaults to the uncapitalized class name (`orderSecurity`), matching the SpEL reference in the annotation automatically.

This approach follows the guidance's recommendation to enforce resource-level checks at the service layer, ensuring every code path that invokes `updateOrder()` — whether through the REST controller or any other caller — is covered by the ownership gate. A method-level annotation on the controller alone would not protect direct service-layer calls, and a check embedded inline in the method would be easy to bypass or forget on related operations (delete, read, list).

## Behaviour changes

The method now denies requests where the authenticated caller does not own the order:

- **Request**: Any authenticated user can invoke the endpoint. Previously all such requests succeeded.
- **After fix**: Requests where `authentication.name` (the caller's username) does not match the order's `customerUsername` are rejected with HTTP 403 before any database modification.
- **Exception handling**: `AccessDeniedException` is raised internally; Spring's `ExceptionTranslationFilter` handles translation to 403 for authenticated callers.
- **Authorization precedence**: The method-level check runs after the controller's role-based check (`hasRole('USER')`), so both gates apply. A caller without the USER role is rejected at the controller layer; a caller with the role but without ownership is rejected at the service layer.
- **Query load**: The fix adds one additional database query per `updateOrder()` call (`findById()` to verify ownership). The result is discarded once ownership is confirmed; the method then performs a second `findById()` to load the order for modification. A production implementation may optimize by reusing the loaded entity, but the test case uses the fixture as-is.
