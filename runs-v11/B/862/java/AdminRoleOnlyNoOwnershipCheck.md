## Verdict

Exploitable. The `updateOrder` method accepts an order ID from an authenticated caller and modifies the order without verifying that the caller owns it. Any authenticated user can modify any order in the system.

## Source

The `orderId` parameter to `updateOrder()`, which originates from an HTTP request and is attacker-controlled. The authenticated user submitting the request can supply any order ID.

## Fix

Add resource-level authorization through a `@PreAuthorize` annotation that verifies the authenticated user owns the order before allowing the update. The fix also requires a security bean to check ownership against the server-loaded order record.

**Vulnerable code:**
```java
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}
```

**Fixed code (service method):**
```java
@PreAuthorize("@orderSecurity.isOrderOwner(#orderId, authentication.name)")
public Order updateOrder(Long orderId, OrderUpdateRequest request) {
    Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

    order.setShippingAddress(request.getShippingAddress());
    order.setStatus(request.getStatus());

    return orderRepository.save(order);
}
```

**Supporting security bean (to be added to the application):**
```java
@Component("orderSecurity")
public class OrderSecurity {
    
    private final OrderRepository orderRepository;
    
    public OrderSecurity(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }
    
    public boolean isOrderOwner(Long orderId, String authenticatedUserId) {
        return orderRepository.findById(orderId)
                .map(order -> order.getOwnerId().equals(authenticatedUserId))
                .orElse(false);
    }
}
```

## Explanation

The fix adds a `@PreAuthorize` annotation using a SpEL expression that delegates to a security bean before the method executes. The bean loads the order from the repository and verifies that the authenticated user's ID matches the order's owner ID. If ownership is not established, Spring Security raises `AccessDeniedException`, which is translated to a 403 response. This ensures that only the order owner (or an administrator with an overriding `@PreAuthorize` rule) can call `updateOrder`. The fix also requires that the application has `@EnableMethodSecurity` configured to activate method-level authorization checks.

## Behaviour changes

The method now requires that the application's Spring Security configuration includes `@EnableMethodSecurity` at the configuration class level. Without this, the `@PreAuthorize` annotation will be ignored and the vulnerability will remain. Additionally, the method will now return 403 Forbidden instead of 200 OK when called by an authenticated user who does not own the order, breaking any existing caller expectations of silent failure or 404 responses for non-existent or non-owned orders. To maintain 404 semantics for non-owned orders (to avoid leaking order existence), an alternative implementation would scope the repository query itself: `findByIdAndOwnerId(orderId, authenticatedUserId)` and catch the empty result to throw `NoSuchElementException`, which would produce 404 without the `@PreAuthorize` change.
