package com.example.catalog;


/** Compile-only collaborator the fixture references but does not ship. */
public class Product {
    private Long id;
    private String name;
    private boolean active;
    public Long getId() { return id; }
    public String getName() { return name; }
    public boolean isActive() { return active; }
}
