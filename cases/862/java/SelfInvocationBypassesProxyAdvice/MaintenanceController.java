package com.example.billing.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.billing.service.InvoiceService;

@RestController
public class MaintenanceController {

    private final InvoiceService invoiceService;

    public MaintenanceController(InvoiceService invoiceService) {
        this.invoiceService = invoiceService;
    }

    // Reachable by any authenticated user - the global security filter chain
    // only requires a valid session here, since this endpoint was meant to
    // be triggered by the nightly batch job, not called directly by a client.
    @PostMapping("/api/maintenance/month-end-cleanup")
    public void runMonthEndCleanup(@AuthenticationPrincipal Object principal) {
        invoiceService.processMonthEndCleanup();
    }
}
