## Verdict
Exploitable

## Source
The `documentId` path variable at line 16 in DocumentController.java, extracted from the HTTP URL without validation of resource ownership

## Fix

**Vulnerable code:**
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

**Fixed code:**
```java
@DeleteMapping("/api/documents/{documentId}")
@PreAuthorize("@documentSecurity.canDelete(#documentId, authentication.name)")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

**Supporting security bean (to be added):**
```java
@Component
public class DocumentSecurity {
    private final DocumentRepository repository;
    
    public DocumentSecurity(DocumentRepository repository) {
        this.repository = repository;
    }
    
    public boolean canDelete(String documentId, String username) {
        // Load the document and verify the authenticated user owns it
        Document doc = repository.findById(documentId);
        return doc != null && doc.getOwnerId().equals(username);
    }
}
```

**Alternative fix using scoped repository (preferable for avoiding information leaks):**

Modify DocumentService.delete() to scope the lookup by owner:
```java
public void delete(String documentId, String ownerId) {
    repository.deleteByIdAndOwnerId(documentId, ownerId);
}
```

Update controller:
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId, 
    @AuthenticationPrincipal UserDetails userDetails) {
    service.delete(documentId, userDetails.getUsername());
    return ResponseEntity.noContent().build();
}
```

Update repository:
```java
public void deleteByIdAndOwnerId(String documentId, String ownerId) {
    // Database query scopes delete to matching owner
}
```

## Explanation
The vulnerability occurs because the delete endpoint accepts a documentId from the URL and deletes it without verifying the authenticated user owns the document. The fix adds an explicit authorization check before performing the delete. The `@PreAuthorize` annotation with a SpEL expression `@documentSecurity.canDelete(#documentId, authentication.name)` calls a security bean method that loads the document and verifies the authenticated user's username matches the document's owner. If the check fails, Spring Security raises `AccessDeniedException`, which `ExceptionTranslationFilter` translates to a 403 Forbidden response. The alternative approach using a scoped repository query (`deleteByIdAndOwnerId`) is preferable because it returns 404 for "not yours" and "does not exist" identically, preventing the endpoint from leaking information about which documents exist in the system.

## Behaviour changes
- The endpoint now requires the authenticated user to own the document before deletion succeeds; an unauthorized user receives 403 (for role/permission gate) or 404 (for scoped lookup).
- The method must be called through Spring's proxy (via dependency injection) rather than directly, to activate the `@PreAuthorize` advice. A direct call to `delete()` on `this` bypasses authorization.
- If using the scoped-query approach, the service method signature changes to accept the owner identifier, requiring callers to pass the authenticated user's identity.
- The `@PreAuthorize` approach does not alter the method signature; the repository still deletes any matching documentId, but the check runs first.

