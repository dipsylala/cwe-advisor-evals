## Verdict

CONFIRMED. Missing Authorization in OrderService.updateOrder() at line 24. The method performs a sensitive database update (save) without any authorization check. While the controller endpoint has role-based protection, the service method itself lacks authorization, allowing direct programmatic invocation without permission validation. This violates Spring Security best practices of applying method-level authorization at the service layer.

## Source

**File**: OrderService.java
**Line**: 24
**Method**: updateOrder(Long orderId, OrderUpdateRequest request)

The updateOrder() method retrieves an order by ID and updates its shipping address and status, then persists the changes via orderRepository.save(order). No authorization check verifies that the authenticated user has the required role to perform this sensitive update operation.

**Data Flow**:
- Source: Any authenticated user can invoke the updateOrder() method (either through the controller endpoint with USER role or directly from other code)
- Sink: orderRepository.save(order) at line 24 performs the state change without authorization
- Gap: Missing @PreAuthorize annotation on the service method; authorization is only enforced at the controller endpoint level, not at the method layer

## Fix

The vulnerability is remediated by adding the `@PreAuthorize` annotation with an ADMIN role requirement to the updateOrder() method, ensuring authorization is enforced at the service layer.

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

## Explanation

The fix adds `@PreAuthorize("hasRole('ADMIN')")` to the updateOrder() method, enforcing that only users with the ADMIN role can update orders. This annotation works in conjunction with Spring Security's method-level authorization (enabled via `@EnableMethodSecurity`), creating an authorization gate at the service layer where the sensitive operation occurs.

**Why this eliminates the weakness:**
- The `@PreAuthorize` annotation intercepts method invocations through Spring's proxy mechanism, checking the caller's authorities before execution
- `hasRole('ADMIN')` verifies that the authenticated user has the `ROLE_ADMIN` authority, making authorization explicit rather than implicit
- By applying the check at the service method rather than only at the controller, the authorization is enforced regardless of how the method is invoked (HTTP endpoint, inter-service calls, scheduled tasks, etc.)
- This follows Spring Security best practices of enforcing authorization at the point where sensitive operations occur

**Security properties preserved:**
- Authentication check remains intact (the caller must be authenticated)
- Method return value and behavior unchanged
- Repository contract preserved
- No silent failures; unauthorized calls raise AccessDeniedException (translated to 403 by ExceptionTranslationFilter)

## Behaviour changes

- Authenticated users with roles other than ADMIN will now receive 403 Forbidden when attempting to update orders
- Users with ADMIN role will continue to update orders normally
- The method's functionality, return type, and exception handling remain unchanged
- AccessDeniedException is raised for unauthorized callers, which Spring Security translates to an appropriate HTTP response (403 for authenticated users)
