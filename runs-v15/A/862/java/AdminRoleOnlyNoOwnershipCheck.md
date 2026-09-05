## Verdict
Missing authorization control. The `updateOrder` method allows any authenticated user to modify any order without verifying ownership or admin role. Access control must be enforced before the state-modifying operation.

## Source
```java
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}
```

The method retrieves an order and modifies it without checking whether the caller has permission to do so.

## Fix
```java
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;

public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    // Verify authorization: check admin role or ownership
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
    
    boolean isOwner = order.getUserId().equals(getUserIdFromAuth(authentication));
    
    if (!isAdmin && !isOwner) {
        throw new AccessDeniedException("User is not authorized to update this order");
    }

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}

private Long getUserIdFromAuth(Authentication authentication) {
    // Extract user ID from authentication principal
    // This assumes the principal has user identity available
    return ((UserPrincipal) authentication.getPrincipal()).getUserId();
}
```

Alternatively, use Spring Security's `@PreAuthorize` or `@PostAuthorize` annotations for declarative authorization:

```java
@PreAuthorize("hasRole('ADMIN') or @orderService.isOwner(#orderId)")
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}

public boolean isOwner(Long orderId) {
    Order order = orderRepository.findById(orderId).orElse(null);
    if (order == null) {
        return false;
    }
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Long currentUserId = ((UserPrincipal) authentication.getPrincipal()).getUserId();
    return order.getUserId().equals(currentUserId);
}
```

## Explanation
CWE-862 occurs when an application fails to check whether a user has permission to perform an action. In this case, the method modifies an order after retrieving it by ID but never validates that the current user is authorized to make that change.

The fix adds an authorization check before the state-modifying operation (`save()`). It verifies that the caller either has the `ROLE_ADMIN` authority or is the owner of the order. If neither condition is met, an `AccessDeniedException` is thrown, preventing unauthorized modification.

The declarative approach using `@PreAuthorize` is preferred when using Spring Security, as it centralizes authorization logic and integrates with Spring Security's SpEL (Spring Expression Language) evaluation.

Authorization checks must occur:
- After identifying which resource is being accessed (line 17: fetch the order)
- Before the state change is persisted (before line 24: the save operation)
- Based on the current user's identity and role, not just authentication status

This ensures that orders can only be modified by users who have explicit permission to do so.
