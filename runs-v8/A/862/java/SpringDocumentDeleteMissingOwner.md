## Verdict
Confirmed. The endpoint accepts any document ID and deletes it without verifying the current user owns or has permission to access the resource.

## Source
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

Line 16: The `@DeleteMapping` handler receives a `documentId` from the URL path and passes it directly to the service layer without any ownership or authorization check.

## Fix
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId, Principal principal) {
    service.deleteIfOwner(documentId, principal.getName());
    return ResponseEntity.noContent().build();
}
```

And update `DocumentService.delete()`:

```java
public void delete(String documentId, String username) {
    Document document = repository.findById(documentId);
    if (document == null) {
        throw new ResourceNotFoundException("Document not found");
    }
    if (!document.getOwner().equals(username)) {
        throw new AccessDeniedException("You do not have permission to delete this document");
    }
    repository.deleteById(documentId);
}
```

And add to `DocumentRepository`:

```java
public Document findById(String documentId) {
    // fetch and return document, including owner field
}
```

## Explanation
The vulnerability occurs because the handler deletes any document matching the provided ID without verifying authorization. The fix adds a `Principal` parameter to capture the current authenticated user, passes it to the service layer, and performs an ownership check before deletion. The service retrieves the document, verifies the current user is the owner, and only proceeds with deletion if authorized. Unauthorized attempts throw `AccessDeniedException` (403 Forbidden) instead of allowing the deletion.
