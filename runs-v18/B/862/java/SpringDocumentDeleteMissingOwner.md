## Verdict
True Positive - CWE-862 (Missing Authorization). The delete endpoint accepts any authenticated user and deletes the document without verifying the caller owns it.

## Source
The vulnerability exists in the call chain:
1. **DocumentController.delete()** (line 16): `@DeleteMapping("/api/documents/{documentId}")` receives a document ID from the URL
2. **DocumentService.delete()** (line 10-11): Passes documentId directly to the repository without authorization
3. **DocumentRepository.deleteById()** (line 4-5): Deletes by ID with no ownership check

The data flow: HTTP path parameter `documentId` → controller method → service method → repository, with no authorization gate before deletion. Any authenticated user can delete any document.

## Fix
The authorization check must occur *before* the deletion operation. Add `@PreAuthorize` at the service layer to verify ownership using a security bean, and create supporting classes to load and verify the document's owner.

### File: DocumentService.java
```java
package cases.authorization;

import org.springframework.security.access.prepost.PreAuthorize;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    @PreAuthorize("@documentSecurity.canDelete(#documentId, authentication.name)")
    public void delete(String documentId) {
        repository.deleteById(documentId);
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

    public boolean canDelete(String documentId, String username) {
        Document document = repository.findById(documentId);
        if (document == null) {
            return false;
        }
        return document.getOwnerId().equals(username);
    }
}
```

### File: Document.java
```java
package cases.authorization;

public class Document {
    private String id;
    private String ownerId;

    public Document(String id, String ownerId) {
        this.id = id;
        this.ownerId = ownerId;
    }

    public String getId() {
        return id;
    }

    public String getOwnerId() {
        return ownerId;
    }
}
```

### File: DocumentRepository.java
```java
package cases.authorization;

public class DocumentRepository {
    public Document findById(String documentId) {
        // Load the document from storage and return it
        // Returns null if the document does not exist
        return null;
    }

    public void deleteById(String documentId) {
    }
}
```

### File: DocumentController.java
```java
package cases.authorization;

import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<Void> delete(@PathVariable String documentId) {
        service.delete(documentId);
        return ResponseEntity.noContent().build();
    }
}
```

## Explanation
The fix adds authorization at the service layer using Spring Security's `@PreAuthorize` annotation with a SpEL expression that invokes a security bean. The security bean's `canDelete()` method loads the document from the repository and verifies the authenticated username matches the document's owner before returning true. Only if the check passes does the service proceed to delete.

The `@PreAuthorize` annotation is placed on the service method rather than the controller because service layer authorization covers all callers that use the bean's proxy, including future background jobs or other services. Method-level security in Spring requires `@EnableMethodSecurity` to be active on the configuration class.

The authorization check occurs before the deletion operation, preventing any damage if the check fails. An unauthorized caller receives an `AccessDeniedException`, which the Spring `ExceptionTranslationFilter` translates to a 403 response.

## Behaviour changes
- **Before**: Any authenticated user can delete any document by calling DELETE /api/documents/{documentId}.
- **After**: Only the document owner (the user whose username matches the document's ownerId) can delete it. Unauthorized deletion attempts receive HTTP 403 (Forbidden). Attempts to delete non-existent documents return null from the repository, causing the authorization check to return false, also resulting in 403 - this does not distinguish "not found" from "not yours" at the HTTP level, which is the secure pattern for guessable identifiers.
