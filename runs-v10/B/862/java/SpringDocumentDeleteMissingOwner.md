## Verdict

exploitable

## Source

`@PathVariable String documentId` at DocumentController.java:17 - untrusted user-supplied document identifier from URL path, passed directly to service layer without ownership verification.

## Fix

**DocumentController.java** (add authorization check at controller level):

```java
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
    @PreAuthorize("@documentSecurity.isOwner(#documentId, authentication.name)")
    public ResponseEntity<Void> delete(@PathVariable String documentId) {
        service.delete(documentId);
        return ResponseEntity.noContent().build();
    }
}
```

**DocumentService.java** (unchanged - authorization happens at controller layer via proxy):

```java
package cases.authorization;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
```

**DocumentSecurity.java** (new bean to verify ownership - must be added):

```java
package cases.authorization;

import org.springframework.stereotype.Component;

@Component
public class DocumentSecurity {
    private final DocumentRepository repository;

    public DocumentSecurity(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean isOwner(String documentId, String username) {
        // Repository must be updated to support ownership checks
        return repository.isOwnedBy(documentId, username);
    }
}
```

**DocumentRepository.java** (update to support ownership verification):

```java
package cases.authorization;

public class DocumentRepository {
    public void deleteById(String documentId) {
    }

    public boolean isOwnedBy(String documentId, String username) {
        // Verify document exists and is owned by the specified user
        // Implementation loads document from database and checks owner
        return false; // placeholder - actual implementation needed
    }
}
```

## Explanation

The vulnerability occurs because the `delete()` endpoint accepts a document ID from the URL without verifying the authenticated user owns that document. Any authenticated user can delete any document by guessing or knowing its ID. The fix adds `@PreAuthorize("@documentSecurity.isOwner(#documentId, authentication.name)")` at the controller method, which intercepts the request before execution and calls a security bean to verify the caller owns the document. The SpEL expression `#documentId` injects the method parameter, and `authentication.name` injects the current username. If the security check fails, Spring Security raises `AccessDeniedException`, which is translated to HTTP 403 Forbidden by the framework's `ExceptionTranslationFilter`. The ownership check is performed by a repository method that loads the document and compares its owner against the authenticated user, implementing the scoped-access pattern described in the guidance.

## Behaviour changes

- **Argument added to authorization evaluation**: `@PreAuthorize` intercepts the method call and evaluates the SpEL expression before the original method body runs. The security bean's `isOwner()` method is invoked with the documentId and username extracted from the request context. Reason: to verify ownership before execution.
- **Access denied requests now raise AccessDeniedException**: Unauthorized users receive HTTP 403 Forbidden instead of a successful 204 No Content response. Reason: to enforce the authorization gate and deny the deletion.
- **New dependency on Spring Security method-level annotations**: Requires `@EnableMethodSecurity` on the application configuration (Spring Security 5.6+). Reason: to activate the `@PreAuthorize` advice on controller methods.
- **New repository method introduced**: `isOwnedBy(documentId, username)` must be implemented in the repository to perform the actual ownership check against the database. Reason: to load the document and verify the caller owns it, not just holds a role.
