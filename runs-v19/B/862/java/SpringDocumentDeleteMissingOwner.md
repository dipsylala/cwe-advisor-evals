## Verdict

Exploitable - Missing Authorization on document deletion endpoint. Any authenticated user can delete any document by manipulating the documentId path parameter without the application verifying ownership.

## Source

**File:** DocumentController.java (line 16)  
**Method:** `delete(@PathVariable String documentId)`  
**Type:** REST endpoint decorated with `@DeleteMapping("/api/documents/{documentId}")`

**Data Flow:**
1. User-supplied `documentId` from URL path → `DocumentController.delete()` parameter
2. Passed to `DocumentService.delete(documentId)` → `DocumentRepository.deleteById(documentId)`
3. Document deleted without any authorization check

**Vulnerability:** The endpoint performs a sensitive action (deleting a document) without verifying the authenticated caller owns the document. The only check is implicit authentication (caller must be logged in), but no ownership or permission validation occurs. An authenticated user with ID `alice` can delete documents owned by user `bob` by simply substituting the documentId in the URL.

## Fix

### File: DocumentService.java

```java
package cases.authorization;

import org.springframework.security.access.prepost.PreAuthorize;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    @PreAuthorize("@documentSecurityService.isOwner(#documentId, authentication.name)")
    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
```

### File: DocumentSecurityService.java

```java
package cases.authorization;

import org.springframework.stereotype.Component;

@Component
public class DocumentSecurityService {
    private final DocumentRepository repository;

    public DocumentSecurityService(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean isOwner(String documentId, String userId) {
        return repository.isOwnedBy(documentId, userId);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public void deleteById(String documentId) {
    }

    public boolean isOwnedBy(String documentId, String userId) {
        // In a real implementation, this would query the database
        // to verify if userId owns the document with documentId.
        // Example: SELECT COUNT(*) FROM documents WHERE id = documentId AND owner_id = userId
        return true;
    }
}
```

## Explanation

The fix adds resource-level authorization through Spring Security's method-level security, checking document ownership before allowing deletion. The `@PreAuthorize` annotation on `DocumentService.delete()` evaluates a SpEL expression at runtime: it calls `documentSecurityService.isOwner(documentId, username)` where `documentId` is the method parameter and `username` is the authenticated caller's principal name. The security bean queries the repository to verify the caller owns the specific document. If the check fails, Spring Security raises `AccessDeniedException`, which `ExceptionTranslationFilter` converts to a 403 Forbidden response for authenticated users. By placing the check on the service method, every code path that deletes documents—whether through the REST controller, scheduled jobs, or other callers—is protected, unlike a controller-only guard that could be bypassed by direct service invocation.

## Behaviour changes

1. **Ownership verification added** - The delete operation now requires the caller to own the document. This enforces data isolation and closes the vulnerability.

2. **Response behavior change for unauthorized calls** - Authenticated users lacking ownership now receive HTTP 403 Forbidden instead of HTTP 204 No Content. This is the correct response and alerts the user they lack permission rather than silently succeeding.

3. **Repository interface expanded** - Added `isOwnedBy(String documentId, String userId)` method to DocumentRepository. This is necessary to support the authorization check and has no impact on the delete behavior itself.

4. **Spring Security dependency assumed** - The fix requires `spring-security-core` (method security via `@PreAuthorize`) and `spring-security-web` (automatic exception translation). These are standard in Spring Security starter; confirm they are present in the project's dependency manifest.

5. **Enable method security configuration** - Spring applications must have method-level security enabled. This requires either `@EnableMethodSecurity` (Spring Security 5.6+) or `@EnableGlobalMethodSecurity(prePostEnabled = true)` on a configuration class. The fix does not add this annotation; confirm it exists in your `SecurityConfig` or similar configuration class.
