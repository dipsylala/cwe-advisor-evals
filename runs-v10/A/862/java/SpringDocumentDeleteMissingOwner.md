## Verdict
Authorization check is missing. The delete endpoint allows any authenticated or unauthenticated user to delete any document without verifying ownership.

## Source
The vulnerability is in `DocumentController.delete()` at line 16-19. The endpoint receives a `documentId` path variable but performs no authorization check before delegating to `service.delete(documentId)`. The service and repository layers also lack any ownership validation.

## Fix
1. Inject `SecurityContextHolder` or use Spring's `@AuthenticationPrincipal` to retrieve the current user.
2. In `DocumentService.delete()`, query the document to verify the current user owns it before calling `repository.deleteById()`.
3. Throw an `AccessDeniedException` (or return 403) if the user does not own the document.
4. Return 404 if the document does not exist, or 403 if the user lacks permission. Do not leak information about document existence to unauthorized users.

Remediated code:

```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(
    @PathVariable String documentId,
    @AuthenticationPrincipal UserDetails principal) {
    if (principal == null) {
        throw new AccessDeniedException("User not authenticated");
    }
    service.delete(documentId, principal.getUsername());
    return ResponseEntity.noContent().build();
}
```

```java
public void delete(String documentId, String username) {
    Document doc = repository.findById(documentId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
    
    if (!doc.getOwner().equals(username)) {
        throw new AccessDeniedException("User does not own this document");
    }
    
    repository.deleteById(documentId);
}
```

## Explanation
The original code performs no authorization check: it deletes any document by ID without verifying the current user owns it. CWE-862 requires that operations check whether the user has permission before executing the operation.

The fix retrieves the current authenticated user, then verifies ownership before delete. If the user is unauthenticated, not the owner, or the document does not exist, the operation fails with an appropriate error (403 Forbidden for authorization failures, 404 for not found). This prevents unauthorized deletion and follows the principle of failing securely—rejecting the operation rather than silently succeeding or leaking whether a document exists to an unauthorized user.
