## Verdict
Confirmed. The delete endpoint does not verify the current user owns the document before deletion, allowing any authenticated user to delete any document.

## Source
The vulnerability is in the delete endpoint at line 16 of DocumentController. It accepts a `documentId` from the URL path and immediately deletes it via the service layer without checking authorization. Neither the controller nor the service verifies that the currently authenticated user is the document's owner.

The call chain:
1. Controller receives DELETE request with a document ID
2. Controller calls `service.delete(documentId)` without user context
3. Service calls `repository.deleteById(documentId)` without verification
4. Repository deletes any document by ID

An attacker can delete another user's document by knowing or guessing their document ID.

## Fix

### File: DocumentController.java
```java
package cases.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        
        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        boolean deleted = service.delete(documentId, currentUser);
        if (!deleted) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.noContent().build();
    }
}
```

### File: DocumentService.java
```java
package cases.authorization;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean delete(String documentId, String currentUser) {
        Document document = repository.findById(documentId);
        if (document == null) {
            return false;
        }
        
        if (!document.getOwner().equals(currentUser)) {
            return false;
        }
        
        repository.deleteById(documentId);
        return true;
    }
}
```

### File: DocumentRepository.java
```java
package cases.authorization;

public class DocumentRepository {
    public Document findById(String documentId) {
        // Fetch and return the document, or null if not found
        return null;
    }
    
    public void deleteById(String documentId) {
    }
}
```

## Explanation
The fix implements authorization checks at two levels:

1. **Controller Level**: Retrieves the currently authenticated user from Spring Security's SecurityContextHolder. This represents the user making the request.

2. **Service Level**: The service now accepts the current user and verifies:
   - The document exists (fetches it from the repository)
   - The current user is the document's owner
   - Only deletes the document if ownership is verified

3. **Repository Enhancement**: Adds a `findById()` method to retrieve documents so ownership can be verified before deletion.

4. **Response Handling**:
   - Returns 403 (Forbidden) if the document exists but the user is not the owner
   - Returns 204 (No Content) on successful deletion
   - Returns 401 (Unauthorized) if no user is authenticated

This ensures that only the document owner can delete their own documents, preventing unauthorized access to other users' data.
