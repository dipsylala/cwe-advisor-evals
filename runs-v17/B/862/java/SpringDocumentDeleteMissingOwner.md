# CWE-862 Remediation: Missing Authorization - SpringDocumentDeleteMissingOwner

## Verdict

The finding is confirmed. The `DELETE /api/documents/{documentId}` endpoint deletes any document without verifying the authenticated user owns it. An authenticated user can delete documents belonging to other users by changing the documentId in the URL path.

## Source

**Vulnerable code path:**
1. `DocumentController.delete(@PathVariable String documentId)` - line 16 receives document ID from URL
2. Calls `DocumentService.delete(documentId)` - line 18
3. Calls `DocumentRepository.deleteById(documentId)` - performs deletion without ownership check

**Weakness:** The delete operation performs a sensitive action (deleting a document) based on user-supplied input (documentId) without verifying the authenticated user owns the document being deleted.

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

    @PreAuthorize("@documentSecurity.isOwner(#documentId, authentication.principal.username)")
    public void delete(String documentId) {
        repository.deleteById(documentId);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public void deleteById(String documentId) {
    }

    public Document findById(String documentId) {
        return null;
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
        Document document = repository.findById(documentId);
        if (document == null) {
            return false;
        }
        return document.getOwnerId().equals(username);
    }
}
```

## Explanation

The fix adds method-level authorization to the `DocumentService.delete()` method using Spring Security's `@PreAuthorize` annotation. The annotation references a custom security bean (`DocumentSecurity`) that verifies the authenticated user owns the document before the deletion is allowed.

**Key changes:**
1. **Added `@PreAuthorize` to service method** - Method-level authorization is enforced at the service layer, ensuring every caller (whether direct or through the controller) is subject to the check.
2. **Security bean loads actual document** - The `DocumentSecurity.isOwner()` method loads the document from the repository and checks server-side whether its `ownerId` matches the authenticated user's username.
3. **Resource ownership verified** - The check is not just a role check but an actual ownership verification against the server-controlled document data.
4. **Safe failure mode** - If the document is not found or the ownership check fails, `isOwner()` returns false, causing Spring Security to raise `AccessDeniedException`, which translates to HTTP 403 for authenticated users attempting unauthorized deletion.

The `DocumentRepository.findById()` method is added to support the security check's document loading requirement. The `Document` class represents the entity with ownership metadata.

## Behaviour changes

**Before fix:**
- Any authenticated user could DELETE `/api/documents/{documentId}` for any document ID
- Response: 204 No Content (success) for any document that exists
- No authorization check occurred

**After fix:**
- DELETE `/api/documents/{documentId}` verifies the caller owns the document via `@PreAuthorize` before execution
- Response: 403 Forbidden if the authenticated user does not own the document
- Response: 204 No Content (success) only if the caller owns the document
- `AccessDeniedException` is raised and translated by `ExceptionTranslationFilter` to a 403 status code for authenticated callers
- Documents cannot be deleted by users other than their owner
