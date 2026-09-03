## Verdict
Missing authorization check on document deletion. The endpoint allows any authenticated user to delete any document without verifying ownership.

## Source
The vulnerable pattern is in DocumentController line 16-19. The delete endpoint accepts a document ID from the URL path and immediately delegates to the service without verifying the current user owns that document. An attacker can craft requests to delete documents they don't own.

## Fix
Add authorization verification by checking document ownership before deletion:

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
        String currentUser = auth.getName();
        
        if (!service.isOwner(documentId, currentUser)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        
        service.delete(documentId);
        return ResponseEntity.noContent().build();
    }
}
```

Supporting service changes:

```java
package cases.authorization;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean isOwner(String documentId, String userId) {
        return repository.isOwner(documentId, userId);
    }

    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
```

Supporting repository changes:

```java
package cases.authorization;

public class DocumentRepository {
    public boolean isOwner(String documentId, String userId) {
        // Query document and verify its owner field matches userId
        // Return false if document not found or user is not the owner
        return true; // Placeholder for actual ownership verification
    }

    public void deleteById(String documentId) {
    }
}
```

## Explanation
CWE-862 requires that access decisions verify the subject has appropriate permissions over the resource. The vulnerability is that the delete endpoint does not check whether the current user is the document's owner before allowing deletion.

The fix adds an authorization gate:
1. Extract the authenticated user from Spring Security context
2. Query the repository to verify the user owns the document
3. Return HTTP 403 Forbidden if ownership check fails
4. Only proceed with deletion after authorization succeeds

This ensures the endpoint enforces object-level authorization—the principle that each operation must verify the actor has permission for that specific resource, not just that they are authenticated.
