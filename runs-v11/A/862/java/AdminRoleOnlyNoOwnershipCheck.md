## Verdict

**CONFIRMED** — Missing Authorization (CWE-862). The `updateOrder` method allows any authenticated user to modify any order by ID without verifying ownership or explicit authorization to access that specific order.

## Source

**File:** OrderService.java, line 24  
**Method:** `updateOrder(Long orderId, OrderUpdateRequest request)`

The vulnerability exists because the method retrieves an order by ID and modifies it without checking whether the current user is authorized to access that order. The method parameter `orderId` is attacker-controlled (supplied by the caller), and no ownership or authorization check verifies that the current user may modify it.

**Call chain:** OrderService.updateOrder() → orderRepository.save() (line 24, sink)

## Fix

```java
package com.example.orders;

import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

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

        // Add authorization check: verify ownership before allowing modification
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!isAuthorizedToModifyOrder(order, auth)) {
            throw new AccessDeniedException("Not authorized to modify this order");
        }

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }

    private boolean isAuthorizedToModifyOrder(Order order, Authentication auth) {
        // Check if user owns the order or is an admin with explicit authorization
        String currentUsername = auth.getName();
        
        // Primary defense: verify order ownership
        if (order.getCustomerId() != null && 
            order.getCustomerId().equals(getCurrentUserId(currentUsername))) {
            return true;
        }
        
        // Secondary defense: admin with explicit authorization scope
        return auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ORDER_ADMIN".equals(a.getAuthority()));
    }

    private Long getCurrentUserId(String username) {
        // Retrieve the current user's ID from the security context or repository
        // This is application-specific; adjust to match your user management
        return userService.getUserIdByUsername(username);
    }
}
```

## Explanation

**Root cause:** The method trusts the `orderId` parameter without verifying that the requesting user has authorization to modify that specific order. Attackers can update any order in the system by guessing or enumerating order IDs.

**Primary defense:** Before modifying the order, check whether the current user owns it. Extract the authenticated user's identity from Spring Security's `SecurityContextHolder` and compare it with the order's customer ID.

**Secondary defense:** For admin users, require an explicit role (`ROLE_ORDER_ADMIN`) rather than a generic admin role. This prevents privilege escalation if a lower-level admin role exists.

**Why this fixes the vulnerability:**
- Line 23-26 (authorization check) now enforces that only the order's owner or an explicitly authorized admin can modify it
- The `orElseThrow()` on line 17-18 is kept to maintain the original 404 behavior for non-existent orders, but is now reached only after authorization succeeds
- The fix applies the principle of checking authorization at the entry point of the sensitive operation, before the sink (`save()` call)

**Verification:** The fix should be tested with:
1. A user attempting to update an order they own (should succeed)
2. A user attempting to update another user's order (should throw `AccessDeniedException`)
3. An admin with `ROLE_ORDER_ADMIN` updating any order (should succeed)
