package com.example.billing.model;

/** Compile-only collaborator the fixture references but does not ship. */
public class Invoice {
    private Long id;
    private boolean voided;
    public Long getId() { return id; }
    public boolean isVoided() { return voided; }
}
