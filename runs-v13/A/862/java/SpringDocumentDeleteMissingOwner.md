## Verdict

The `delete` endpoint in `DocumentController` is vulnerable to CWE-862 (Missing Authorization). It allows any authenticated user to delete any document without verifying ownership. The vulnerability exists because the service layer performs the deletion without checking if the current user owns the requested document.

## Source

The vulnerability originates at line 16 in `DocumentController.java`:

```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

The endpoint deletes a document based solely on its ID without verifying that the current user owns it.

## Fix

Add ownership verification in the `DocumentService.delete()` method before performing the deletion. Use Spring Security to retrieve the current authenticated user, then check if that user owns the document:

```java
package cases.authorization;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId) {
        // Get current authenticated user
        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
        
        // Verify ownership before deletion
        if (!isOwner(documentId, currentUser)) {
            throw new AccessDeniedException("You are not authorized to delete this document");
        }
        
        repository.deleteById(documentId);
    }
    
    private boolean isOwner(String documentId, String userId) {
        // Query repository to verify document ownership
        // This assumes the Document entity has an owner or userId field
        // Implementation depends on your Document model
        return repository.isOwnedBy(documentId, userId);
    }
}
```

Update `DocumentRepository` to include an ownership check method:

```java
package cases.authorization;

public class DocumentRepository {
    public void deleteById(String documentId) {
    }
    
    public boolean isOwnedBy(String documentId, String userId) {
        // Query the database to verify the document belongs to the user
        // Return true only if userId matches the document's owner
        return false; // Implementation depends on your schema
    }
}
```

## Explanation

CWE-862 occurs when an application performs an operation without verifying that the authenticated user has permission to perform it on that specific resource. In this case, the endpoint accepts a document ID and deletes it without confirming the user owns it.

The fix implements resource-level authorization by:

1. **Retrieving the authenticated user**: `SecurityContextHolder.getContext().getAuthentication().getName()` obtains the current user's identity from Spring Security.

2. **Verifying ownership**: Before deletion, the service queries the repository to confirm the document belongs to the authenticated user.

3. **Denying unauthorized access**: If the user does not own the document, `AccessDeniedException` is thrown, resulting in a 403 Forbidden response.

This pattern ensures that each user can only delete documents they own, preventing unauthorized data deletion.
