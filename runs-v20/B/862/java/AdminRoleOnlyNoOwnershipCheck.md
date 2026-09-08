## Verdict

exploitable

## Source

The identifier that reaches the sink unchecked: `orderId`, the `Long` parameter of `OrderService.updateOrder(Long orderId, OrderUpdateRequest request)`. It is attacker-influenced (an order identifier supplied by whatever caller invokes this method - typically a path/body parameter on the controller that is not part of the provided call chain) and is used, unmodified and unverified against the caller, to load and then persist a specific `Order` record.

## Fix

### File: OrderService.java

```java
package com.example.orders;

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
        String caller = authentication == null ? null : authentication.getName();
        if (caller == null || !caller.equals(order.getOwnerUsername())) {
            throw new NoSuchElementException("Order not found: " + orderId);
        }

        order.setShippingAddress(request.getShippingAddress());
        order.setStatus(request.getStatus());

        return orderRepository.save(order);
    }
}
```

## Explanation

`updateOrder` loaded the order strictly by its primary key and mutated/persisted it without ever comparing the record to the caller: any authenticated caller who could reach this method (in this design, gated only by an admin role check upstream, outside this call chain) could update any order by supplying any `orderId`, not only orders they are entitled to touch - a role check confirms *what* the caller may do, not *which record* they may do it to. The fix reads the current principal from `SecurityContextHolder` (the standard Spring Security accessor, requiring no change to the method's signature or callers) and compares it to the order's owner before any mutation happens. On mismatch it raises the exact same `NoSuchElementException` already used for "no such order", so a caller who is not the owner gets a response indistinguishable from the order not existing at all - this avoids turning the identifier space into an enumeration oracle (a distinct "forbidden" response would confirm the record exists), consistent with the knowledge base's guidance to scope resource-level authorization checks so that "not yours" and "does not exist" resolve identically. The pre-existing role gate (implied by the finding name and not visible in this file) is left untouched; this fix adds only the missing ownership check, it does not change or duplicate the role logic.

## Behaviour changes

- Added ownership check: a caller whose identity does not match `order.getOwnerUsername()` now receives `NoSuchElementException` instead of having the order updated. This is the fix itself, not incidental.
- No change to the method signature, return type, or the "not found" failure behaviour for a genuinely missing `orderId` - both failure paths now share one exception type and message shape, by design (see Explanation).
- No change to what is persisted when the check passes: `shippingAddress` and `status` are copied and saved exactly as before.

**Assumptions** (confidence: medium - lowered by these):
- Only `OrderService.java` was in scope for this finding; `Order.java`, `OrderController.java`, `OrderRepository.java`, and `OrderUpdateRequest.java` were not read. `Order` is assumed to expose an owner-identifying accessor, named `getOwnerUsername()` here to match against `Authentication.getName()` (a username/principal name). If the real entity instead exposes an owner id (e.g. `getOwnerId()`) or a different accessor name, substitute that comparison for `order.getOwnerUsername()` accordingly - the fix's structure (load, compare to caller, fail closed with the existing not-found exception) carries over unchanged.
- Spring Security is assumed to be present on the classpath. This file does not import it directly, but the finding's own framing ("admin role only") implies role-based authorization is already enforced elsewhere in this Spring application (visible imports confirm Spring, via `org.springframework.stereotype.Service`), making Spring Security the standard mechanism for that role check.
- The existing role check (admin-only) is assumed to already exist upstream of this method (controller, filter chain, or an annotation on a class not in this call chain) and is left as-is; this fix does not re-implement or duplicate it.
- **Verification**: `javac` compiled the fixed `OrderService.java` successfully against minimal stub versions of `Order`, `OrderRepository`, `OrderUpdateRequest`, and the Spring/Spring Security types it references (no compiler errors); the stubs' method signatures were inferred only from how those types are used in the original file plus the assumed `getOwnerUsername()` accessor, since the real files were out of scope. Real compilation against the actual `Order` entity still depends on the accessor-name assumption above holding.
