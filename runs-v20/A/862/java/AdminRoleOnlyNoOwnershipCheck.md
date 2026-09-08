## Verdict

True positive. `OrderService.updateOrder` loads an order by an attacker-controlled ID and saves changes to it without ever checking that the authenticated caller is the order's owner.

## Source

`OrderController.updateOrder` (`PUT /api/orders/{orderId}`) takes `orderId` directly from the URL path variable and passes it straight into `orderService.updateOrder(orderId, request)`. The endpoint is gated only by `@PreAuthorize("hasRole('USER')")`, which confirms the caller is logged in as a standard user but says nothing about which order they may touch. Any authenticated user can therefore change `orderId` in the URL and edit another user's order. The data flows unchecked into `orderRepository.findById(orderId)` and then into `orderRepository.save(order)` in `OrderService`, which is the sink flagged at line 24.

## Fix

### File: OrderService.java

```java
package com.example.orders;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
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

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication != null ? authentication.getName() : null;
        if (currentUsername == null || !currentUsername.equals(order.getCustomerUsername())) {
            throw new AccessDeniedException("Not authorized to update order: " + orderId);
        }

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }
}
```

## Explanation

The role check in `OrderController` establishes authentication, not authorization over the specific resource: it proves the caller has role `USER`, not that the caller owns order `orderId`. That is the textbook CWE-862 gap - an authorization decision is missing at the point where the object is actually accessed.

The fix adds the missing object-level check inside `OrderService.updateOrder`, right after the order is loaded and before any field is mutated or persisted. It reads the authenticated principal's name from `SecurityContextHolder` (Spring Security's standard per-request context, already populated by the time `@PreAuthorize` has run) and compares it against `order.getCustomerUsername()`, the field that already records the order's owner. A mismatch - or no authentication at all - throws `AccessDeniedException`, which Spring Security's exception handling maps to an HTTP 403 for an authenticated caller, so a user who is logged in but not the owner is rejected rather than silently allowed through or given a misleading 404. Because the update only proceeds when the caller matches `order.getCustomerUsername()`, an authenticated user can no longer edit another user's order by supplying a different `orderId`, which closes the horizontal-privilege-escalation path the finding identified. No public method signature or controller behavior changes, so the existing `@PreAuthorize("hasRole('USER')")` check continues to do its job as the first-line authentication gate, with this change adding the ownership check the endpoint was missing.
