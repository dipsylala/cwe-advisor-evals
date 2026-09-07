package com.example.security.apikey;


import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;

/** Compile-only collaborator the fixture references but does not ship. */
public class ApiKeyRecord {
    public String getClientId() { return null; }
    public String getHashedKey() { return null; }
    public Collection<? extends GrantedAuthority> getAuthorities() { return java.util.Collections.emptyList(); }
}
