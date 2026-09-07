package com.example.security.apikey;


import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/** Compile-only collaborator the fixture references but does not ship. */
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;
    private final Object principal;
    private final Object credentials;
    public ApiKeyAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
    }
    public ApiKeyAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }
    @Override public Object getCredentials() { return credentials; }
    @Override public Object getPrincipal() { return principal; }
}
