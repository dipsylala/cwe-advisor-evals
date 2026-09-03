## Verdict

Exploitable. The `updateOrder()` method at line 16 receives an `orderId` parameter from an HTTP request and performs a sensitive action (persisting order modifications) without any authorization check to verify the authenticated caller is permitted to modify this specific order. An authenticated user can update any order by guessing or enumerating order IDs.

## Source

Authenticated user supplies `orderId` via HTTP request to `updateOrder()` method (line 16). The request object and order ID are attacker-controlled.

## Fix

**Vulnerable code:**

```java
@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return orderRepository.save(order);
    }
}
```

**Fixed code:**

```java
@Service
public class OrderService {

    private final OrderRepository orderRepository;
    private final OrderSecurity orderSecurity;

    public OrderService(OrderRepository orderRepository, OrderSecurity orderSecurity) {
        this.orderRepository = orderRepository;
        this.orderSecurity = orderSecurity;
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

**Supporting bean pattern** (required for the fix to work):

```java
@Component
public class OrderSecurity {
    
    private final OrderRepository orderRepository;
    
    public OrderSecurity(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }
    
    public boolean isOwner(Long orderId, String username) {
        return orderRepository.findById(orderId)
                .map(order -> order.getOwnerId().equals(username))
                .orElse(false);
    }
}
```

## Explanation

The fix adds a `@PreAuthorize` annotation to the `updateOrder()` method using a SpEL expression that calls an `OrderSecurity` bean's `isOwner()` method. This bean loads the order from the repository and verifies that the authenticated user (extracted from `authentication.name`) owns the order before the update is permitted. The annotation is evaluated before the method executes, and an unauthorized call raises `AccessDeniedException`, which Spring's `ExceptionTranslationFilter` converts to a 403 response for authenticated callers. The `OrderSecurity` bean is injected into the service so the ownership check is centralized and reusable. By scoping the authorization check to resource ownership rather than just role, an authenticated user can only update orders they own, even if they have sufficient role permissions. The fix also removes the SAST finding comment as it is no longer applicable.

## Behaviour changes

- Added constructor parameter: `OrderSecurity orderSecurity` to inject the security bean
- Added `@PreAuthorize` annotation with SpEL expression referencing the method parameter `#orderId` and `authentication.name` from the security context
- Unauthorized calls now raise `AccessDeniedException` instead of proceeding; Spring Security translates this to an HTTP 403 response
- No changes to return value, arguments passed to `orderRepository.save()`, or the order modification logic itself
