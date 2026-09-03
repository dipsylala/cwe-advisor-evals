## Verdict

Exploitable. The endpoint allows any authenticated user to delete any document without verifying ownership. An attacker can delete documents belonging to other users by guessing or enumerating document IDs.

## Source

The `documentId` path parameter from an HTTP DELETE request to `/api/documents/{documentId}`.

## Fix

**Add authorization to the service layer using `@PreAuthorize`:**

```java
// DocumentService.java - FIXED
package cases.authorization;

import org.springframework.security.access.prepost.PreAuthorize;

public class DocumentService {
    private final DocumentRepository repository;
    private final DocumentSecurityService securityService;

    public DocumentService(DocumentRepository repository, DocumentSecurityService securityService) {
        this.repository = repository;
        this.securityService = securityService;
    }

    @PreAuthorize("@documentSecurityService.isOwner(#documentId, authentication.name)")
    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
```

**Create a security service bean that verifies ownership:**

```java
// DocumentSecurityService.java - NEW
package cases.authorization;

import org.springframework.stereotype.Service;

@Service
public class DocumentSecurityService {
    private final DocumentRepository repository;

    public DocumentSecurityService(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean isOwner(String documentId, String username) {
        // Load the document from the repository and verify the current user owns it
        // This is a pattern example; adapt to your actual Document entity and ownership model
        Document document = repository.findById(documentId);
        if (document == null) {
            return false;
        }
        return document.getOwnerId().equals(username);
    }
}
```

**Optionally add `@PreAuthorize` at the controller level for defense in depth:**

```java
// DocumentController.java - OPTIONAL
package cases.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentController {
    private final DocumentService service;

    public DocumentController(DocumentService service) {
        this.service = service;
    }

    @DeleteMapping("/api/documents/{documentId}")
    @PreAuthorize("@documentSecurityService.isOwner(#documentId, authentication.name)")
    public ResponseEntity<Void> delete(@PathVariable String documentId) {
        service.delete(documentId);
        return ResponseEntity.noContent().build();
    }
}
```

**Ensure `@EnableMethodSecurity` is configured (if not already present):**

```java
// SecurityConfiguration.java - ADD OR VERIFY
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {
    // existing configuration
}
```

## Explanation

The vulnerability stems from the absence of authorization checks on the `delete()` method. The endpoint verifies only that a caller is authenticated (logged in) but never checks whether they own the document they are deleting. The fix adds method-level authorization using Spring Security's `@PreAuthorize` annotation with SpEL expressions that invoke a custom security bean (`DocumentSecurityService`). This bean loads the document from the repository and verifies that the authenticated user matches the document's owner before allowing deletion to proceed. By placing the check at the service layer and annotating the `delete()` method directly, every caller—whether through the controller or invoked elsewhere—must pass the ownership check. The `@PreAuthorize` annotation raises `AccessDeniedException` when the check fails, which Spring's `ExceptionTranslationFilter` translates into a 403 Forbidden response for authenticated callers. This enforces the CWE-862 principle that every sensitive action (state change, data deletion) must have an explicit, server-side authorization check before execution.

## Behaviour changes

- **Request rejection:** DELETE requests to `/api/documents/{documentId}` now return 403 Forbidden if the authenticated user does not own the document, instead of succeeding.
- **Request approval:** Requests from the document owner continue to succeed with 204 No Content as before.
- **Service invocation:** Direct invocations of `DocumentService.delete()` from outside an HTTP context raise `AccessDeniedException` if the ownership check fails, forcing the caller to handle authorization explicitly.
- **Dependency injection:** `DocumentService` now requires a `DocumentSecurityService` constructor parameter to verify ownership; this change is transparent to callers using Spring's dependency injection but must be reflected in any manual instantiation (test mocks or manual instantiation patterns must provide both dependencies).
