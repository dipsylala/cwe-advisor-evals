## Verdict

**CWE-862: Missing Authorization** confirmed.

The `updateOrder` method performs a sensitive action (persisting changes to an order) without checking whether the authenticated caller is authorized to do so. Any logged-in user can update any order by ID. The method must enforce a role-based authorization check before the order is modified.

## Source

The `updateOrder` method at line 16 of `OrderService.java` retrieves an order by ID supplied by the caller, modifies it, and persists it via `orderRepository.save()` at line 24. The data flow is:

1. Caller supplies `orderId` as a parameter
2. Method retrieves the order from the repository (line 17-18)
3. Method modifies order state (lines 20-21)
4. **Sink**: Method persists the modified order without any authorization check (line 24)

The vulnerability is the absence of an explicit authorization check before the save operation. The method verifies neither that the caller holds a required role nor that the caller owns the order.

## Fix

Add `@PreAuthorize("hasRole('ADMIN')")` annotation to the method:

```java
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Order updateOrder(Long orderId, OrderUpdateRequest request) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new NoSuchElementException("Order not found: " + orderId));

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }
}
```

**API verification:**
- `@PreAuthorize` is from `org.springframework.security.access.prepost` (Spring Security 3.0+)
- `hasRole('ADMIN')` is a SpEL built-in that checks for the authority `ROLE_ADMIN`
- The annotation requires `@EnableMethodSecurity` to be active on the application configuration (Spring Security 5.6+)

**Compilation check:**
The fixed code compiles against Spring Security 6.x without errors. The annotation is applied at the method level and will be evaluated at runtime by Spring's method-level security proxy.

## Explanation

The `@PreAuthorize("hasRole('ADMIN')")` annotation enforces role-based authorization by intercepting calls to the method at the Spring proxy layer. Before the method body executes, Spring Security verifies that the authenticated user holds the `ROLE_ADMIN` authority. If the user lacks this role, an `AccessDeniedException` is raised, which `ExceptionTranslationFilter` converts to a 403 response.

This closes the vulnerability by:
1. Making the authorization requirement explicit and centralized (not scattered in one-off checks)
2. Leveraging Spring's standard method-level security mechanism used elsewhere in well-secured applications
3. Ensuring the check runs before any state change occurs (the `save()` call)
4. Providing a deny-by-default posture - the method now rejects any caller lacking the required role

The fix preserves the method's existing behavior for authorized callers: it still retrieves the order, modifies it, and persists the changes. Only the authorization gate is added.

## Behaviour changes

- **Before**: Any authenticated user can update any order.
- **After**: Only users with the `ROLE_ADMIN` authority can update orders. Unauthorized users receive a 403 Forbidden response; the method body does not execute.
- **Error handling**: If `@EnableMethodSecurity` is not configured, the annotation is ignored silently and the vulnerability remains. Configuration must be verified: the application must have `@EnableMethodSecurity` on a `@Configuration` class or use Spring Boot's security auto-configuration.
- **Testing requirement**: The fix should be verified with a `@WithMockUser(roles = "ADMIN")` MockMvc test that confirms authorized access works, and a `@WithMockUser(roles = "USER")` test that confirms unauthorized access returns 403.
