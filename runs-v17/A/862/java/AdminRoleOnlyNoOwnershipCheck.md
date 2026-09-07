## Verdict

**CONFIRMED**. The `updateOrder` method lacks authorization checks and permits any authenticated user to modify any order. The vulnerability exists at line 24 where the order is persisted without verifying the caller's ownership or administrative privilege.

## Source

```java
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    return orderRepository.save(order);  // Line 24: Sink - no authorization performed
}
```

The method retrieves an order by ID and saves changes without checking whether the current user owns the order or holds administrative privileges.

## Fix

### File: OrderService.java

```java
package com.example.orders;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

        // Authorization check: user must be owner or admin
        if (!isAuthorizedToUpdateOrder(order)) {
            throw new AccessDeniedException("User is not authorized to update this order");
        }

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return orderRepository.save(order);
    }

    private boolean isAuthorizedToUpdateOrder(Order order) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Check if user has ADMIN role
        if (authentication != null) {
            for (GrantedAuthority authority : authentication.getAuthorities()) {
                if (authority.getAuthority().equals("ROLE_ADMIN")) {
                    return true;
                }
            }
        }
        
        // Check if user is the owner of the order
        if (authentication != null && order.getUserId() != null) {
            String currentUserId = authentication.getName();
            return order.getUserId().equals(currentUserId);
        }
        
        return false;
    }
}
```

## Explanation

The fix introduces an authorization check before persisting any changes to an order:

1. **Inject SecurityContext**: Retrieve the current authenticated user via Spring Security's `SecurityContextHolder`.

2. **Check administrative role**: First verify if the user holds the `ROLE_ADMIN` authority, which grants universal access to update any order.

3. **Check ownership**: If not an admin, verify that the user's ID matches the order's `userId` field, ensuring users can only modify orders they own.

4. **Deny by default**: The method throws `AccessDeniedException` if neither condition is met, enforcing a deny-by-default authorization posture.

This dual-path authorization (admin override OR ownership check) ensures that:
- Administrators can manage any order
- Regular users can modify only their own orders
- Any unauthorized access attempt raises an exception, preventing silent or implicit grants

The `isAuthorizedToUpdateOrder()` method is extracted for clarity and testability, making the authorization logic explicit and auditable.

