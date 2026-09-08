## Verdict

The vulnerability is confirmed. The DELETE endpoint at line 16 of DocumentController does not verify that the current user owns the document before allowing deletion. Any authenticated user can delete any document by providing its ID.

## Source

The call chain flows from:
1. **DocumentController.delete()** (line 16-20): Accepts a documentId path variable and calls service.delete() without authorization checks
2. **DocumentService.delete()** (line 10-12): Passes documentId to repository without verifying ownership
3. **DocumentRepository.deleteById()** (line 4-5): Executes the deletion without checking document ownership

The missing control is an ownership check between receiving the user request and executing the database delete operation.

## Fix

### File: DocumentController.java

```java
package cases.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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
    public ResponseEntity<Void> delete(@PathVariable String documentId, Authentication authentication) {
        String currentUser = authentication.getName();
        service.delete(documentId, currentUser);
        return ResponseEntity.noContent().build();
    }
}
```

### File: DocumentService.java

```java
package cases.authorization;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId, String currentUser) {
        Document document = repository.findById(documentId);
        
        if (document == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found");
        }
        
        if (!document.getOwner().equals(currentUser)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }
        
        repository.deleteById(documentId);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public Document findById(String documentId) {
        // Fetch document from database
        return null;
    }
    
    public void deleteById(String documentId) {
    }
}
```

### File: Document.java

```java
package cases.authorization;

public class Document {
    private String id;
    private String owner;

    public Document(String id, String owner) {
        this.id = id;
        this.owner = owner;
    }

    public String getId() {
        return id;
    }

    public String getOwner() {
        return owner;
    }
}
```

## Explanation

The fix adds authorization checks at two critical points:

1. **Controller layer**: The `Authentication` object is injected to retrieve the current user's identity via `authentication.getName()`. This user identifier is passed to the service layer.

2. **Service layer**: Before deletion, the service fetches the document to check its owner. If the document doesn't exist, it returns 404 (Not Found). If the owner doesn't match the current user, it returns 403 (Forbidden). Only when ownership is verified does deletion proceed.

3. **Repository layer**: Added `findById()` to support ownership verification, and kept `deleteById()` as the deletion operation.

4. **Model class**: Added a `Document` class to represent documents with their owner information.

This approach ensures that users can only delete documents they own, preventing the authorization bypass that allows deletion of other users' documents.

