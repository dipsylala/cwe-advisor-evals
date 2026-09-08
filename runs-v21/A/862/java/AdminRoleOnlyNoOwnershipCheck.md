## Verdict
The `updateOrder` method in OrderService.java lacks authorization checks. Any authenticated user can update any order, even if they do not own it and do not have administrative privileges. This violates CWE-862 (Missing Authorization).

## Source
The vulnerable sink is at line 24 in OrderService.java, where `orderRepository.save(order)` persists order modifications without verifying that the current user has permission to modify the target order. The method only verifies order existence (line 17-18) but performs no authorization.

## Fix

### File: OrderService.java
```java
package com.example.orders;

import org.springframework.stereotype.Service;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.AccessDeniedException;

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

        // Authorization check: user must be admin or owner of the order
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
        
        Long currentUserId = getCurrentUserId();
        boolean isOwner = order.getUserId().equals(currentUserId);
        
        if (!isAdmin && !isOwner) {
            throw new AccessDeniedException("User is not authorized to update this order");
        }

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }

    private Long getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Object principal = auth.getPrincipal();
        
        if (principal instanceof CustomUserDetails) {
            return ((CustomUserDetails) principal).getUserId();
        }
        
        throw new IllegalStateException("Unable to determine current user");
    }
}
```

## Explanation
The fix introduces explicit authorization logic before the save operation:

1. **Role-based authorization**: Extracts the current user's authorities from Spring Security's SecurityContext and checks for `ROLE_ADMIN`. Admins are permitted to update any order.

2. **Ownership authorization**: Retrieves the current user's ID via `getCurrentUserId()` and compares it with the order's owner. The order can only be updated by its owner.

3. **Enforcement**: If the user is neither an admin nor the order owner, an `AccessDeniedException` is thrown, preventing the update from proceeding to the repository save.

This dual-check approach satisfies both administrative use cases and user-owned resource scenarios, directly remediating the missing authorization at the persistence sink.
