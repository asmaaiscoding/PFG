package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {

    @Autowired
    private InvoiceRepository invoiceRepository;

    // Vulnerable: no auth, no ownership check, IDOR via {id}.
    @GetMapping("/{id}")
    public Invoice getInvoice(@PathVariable Long id) {
        return invoiceRepository.findById(id);
    }

    // Vulnerable: requires auth but no role check, missing ownership.
    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public void deleteInvoice(@PathVariable Long id) {
        invoiceRepository.deleteById(id);
    }

    // Safe: ownership check via repository method name.
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/owned/{id}")
    public Invoice getMyInvoice(@PathVariable Long id) {
        return invoiceRepository.findByIdAndByOwner(id);
    }

    // Public health endpoint.
    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
