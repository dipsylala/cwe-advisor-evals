## Verdict
CONFIRMED - Missing authorization check. The `updateOrder` method allows any authenticated user to modify any order without verifying ownership.

## Source
HTTP request parameter `orderId` - any authenticated caller can supply any order ID.

## Fix
Add method-level authorization using `@PreAuthorize` with a security bean that verifies the caller owns the order before the method executes.

### File: OrderService.java
```java
package com.example.orders;

import org.springframework.stereotype.Service;
import org.springframework.security.access.prepost.PreAuthorize;

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

@Component
public class OrderSecurity {
    
    private final OrderRepository orderRepository;
    
    public OrderSecurity(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }
    
    public boolean isOwner(Long orderId, String username) {
        return orderRepository.findById(orderId)
                .filter(order -> {
                    String ownerId = order.getOwnerId();
                    return ownerId != null && ownerId.equals(username);
                })
                .isPresent();
    }
}
```

## Explanation
The fix adds method-level authorization through Spring Security's `@PreAuthorize` annotation, which enforces the check before the method body executes. The SpEL expression `@orderSecurity.isOwner(#orderId, authentication.name)` delegates to a security bean that verifies the caller owns the order.

The `OrderSecurity` bean loads the order and compares its owner ID against the authenticated username. If the order doesn't exist or is not owned by the caller, `isOwner()` returns false, triggering an `AccessDeniedException` that Spring Security translates to HTTP 403. This prevents unauthorized access at the application boundary.

The approach follows Spring Security best practices: centralized authorization via decorators at the service layer ensures every code path that invokes `updateOrder` is protected, not only HTTP calls. Authorization is declarative (separated from business logic), and the check covers the specific resource (order ownership) not just a broad role.

## Behaviour changes
- `updateOrder()` now requires ownership of the order before modifications execute
- Unauthorized requests (authenticated user calling with an order they don't own) receive HTTP 403 Forbidden instead of succeeding
- No other method signatures or business logic changes; the update operation remains identical for authorized callers
- The findById lookup in the method body now executes only for authorized callers; the authorization check runs first via the proxy
