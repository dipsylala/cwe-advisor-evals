## Verdict

Exploitable - the method allows any authenticated user to update any order without verifying ownership.

## Source

The `orderId` parameter received from the REST API caller. The method retrieves the order by ID without confirming the caller owns it, then modifies and saves it.

## Fix

**Vulnerable code:**
```java
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    return orderRepository.save(order);
}
```

**Fixed code:**
```java
@PreAuthorize("@orderSecurity.checkOrderOwnership(#orderId, authentication.name)")
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}
```

The required `OrderSecurity` bean:
```java
@Component
public class OrderSecurity {
    private final OrderRepository orderRepository;

    public OrderSecurity(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public boolean checkOrderOwnership(Long orderId, String username) {
        return orderRepository.findByIdAndOwner(orderId, username).isPresent();
    }
}
```

And the scoped repository method:
```java
Optional<Order> findByIdAndOwner(Long id, String owner);
```

## Explanation

The fix adds method-level authorization via `@PreAuthorize` that checks resource ownership before the method executes. The SpEL expression `@orderSecurity.checkOrderOwnership(#orderId, authentication.name)` calls a security bean that verifies the authenticated user owns the order by its ID and username. The repository method `findByIdAndOwner` is scoped to return the order only if it belongs to the specified owner; if the user does not own the order, the query returns empty and the check fails with `AccessDeniedException`, which Spring Security's `ExceptionTranslationFilter` translates to a 403 response. This prevents unauthorized modification of any order, ensuring only the owner can update their own order's shipping address and status.

## Behaviour changes

- The method now raises `AccessDeniedException` if the caller does not own the order, which is translated to HTTP 403 by Spring Security. Previously, any authenticated user could update any order.
- The SpEL expression `authentication.name` extracts the authenticated principal's name; this assumes Spring Security is active in the application context and the principal name matches the owner field in the Order entity. If a different user identifier is stored (e.g., user ID rather than username), adjust the expression to use `authentication.principal.id` or retrieve it from a user service bean.
- Requires `@EnableMethodSecurity` (Spring Security 5.6+) or `@EnableGlobalMethodSecurity` (earlier versions) to be configured on the application, otherwise the `@PreAuthorize` annotation will be ignored and the vulnerability will remain.

