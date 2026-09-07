package com.example.billing.repository;

import java.util.List;
import com.example.billing.model.Invoice;

/** Compile-only collaborator the fixture references but does not ship. */
public interface InvoiceRepository {
    void deleteById(Long id);
    List<Invoice> findAllByVoidedTrue();
}
