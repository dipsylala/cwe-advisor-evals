package com.example.orders;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    // Confirms the caller is logged in with a standard user role, but does not
    // verify that the caller is the owner of the order being updated - any
    // authenticated user can edit any order by changing orderId in the URL.
    @PutMapping("/{orderId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Order> updateOrder(@PathVariable Long orderId,
                                              @RequestBody OrderUpdateRequest request) {
        Order updated = orderService.updateOrder(orderId, request);
        return ResponseEntity.ok(updated);
    }
}
