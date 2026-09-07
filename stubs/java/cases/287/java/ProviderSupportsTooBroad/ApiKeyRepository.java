package com.example.security.apikey;


/** Compile-only collaborator the fixture references but does not ship. */
public interface ApiKeyRepository {
    ApiKeyRecord findByClientId(String clientId);
}
