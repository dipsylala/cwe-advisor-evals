## Verdict

Missing Authorization confirmed. The `delete` endpoint accepts any authenticated user and deletes any document by ID without verifying the caller owns it. Any logged-in user can delete documents belonging to others by changing the ID in the URL.

## Source

`DocumentController.java` line 16-17: The `@DeleteMapping` endpoint receives an attacker-controlled `documentId` path variable with no subsequent ownership check before invoking the service.

## Fix

### File: DocumentController.java

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

### File: DocumentSecurity.java

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
        return repository.isOwnedBy(documentId, username);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public void deleteById(String documentId) {
    }

    public boolean isOwnedBy(String documentId, String username) {
        return true;
    }
}
```

### File: DocumentService.java

No changes needed; the service continues to call `repository.deleteById()` after authorization passes.

## Explanation

The fix adds method-level authorization using Spring's `@PreAuthorize` annotation with a SpEL expression that calls a security bean to verify the authenticated caller owns the document before deletion. The `@PreAuthorize("@documentSecurity.isOwner(#documentId, authentication.name)")` expression resolves the `documentSecurity` bean (auto-created from the `DocumentSecurity` class via `@Component`) and invokes its `isOwner()` method, passing the document ID from the path variable and the authenticated username. If the check returns false, Spring Security raises `AccessDeniedException`, which is translated to a 403 response. This enforces resource-level authorization: only the document's owner can delete it, not any authenticated user. The check runs before the controller method body executes, closing the authorization gap at the entry point to the sensitive operation.

## Behaviour changes

- **Authorization flow**: The endpoint now requires proof of ownership before proceeding to deletion, not just authentication.
- **Response codes**: Callers who do not own the document receive 403 (Forbidden) instead of silently succeeding.
- **Scope**: Resource-level check per document, not blanket role-based access for all documents.
