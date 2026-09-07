## Verdict

Exploitable. The endpoint accepts an authenticated request and deletes a document by ID without verifying the caller owns the document or has permission to delete it.

## Source

`@PathVariable String documentId` in `DocumentController.delete()` at line 16, supplied by the HTTP request URL path.

## Fix

**Vulnerable code:**
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);  // No authorization check
    return ResponseEntity.noContent().build();
}
```

**Fixed code - Option 1 (Method-level authorization with ownership bean):**
```java
@DeleteMapping("/api/documents/{documentId}")
@PreAuthorize("@documentSecurity.canDelete(#documentId, authentication.name)")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

Then create a security bean (e.g., in the same package or a security configuration):
```java
@Component
public class DocumentSecurity {
    private final DocumentRepository repository;

    public DocumentSecurity(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean canDelete(String documentId, String username) {
        Document doc = repository.findById(documentId);
        return doc != null && doc.getOwnerId().equals(username);
    }
}
```

**Fixed code - Option 2 (Repository scoped by owner):**
Modify `DocumentService.delete()` to accept the owner/username and scope the deletion:
```java
@DeleteMapping("/api/documents/{documentId}")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<Void> delete(@PathVariable String documentId, 
                                    @AuthenticationPrincipal UserDetails userDetails) {
    String username = userDetails.getUsername();
    // Delete only if the document belongs to this user
    boolean deleted = service.deleteByIdAndOwner(documentId, username);
    if (!deleted) {
        return ResponseEntity.notFound().build();
    }
    return ResponseEntity.noContent().build();
}
```

Then update `DocumentService`:
```java
public boolean deleteByIdAndOwner(String documentId, String ownerId) {
    return repository.deleteByIdAndOwnerId(documentId, ownerId);
}
```

And update `DocumentRepository` (using Spring Data JPA):
```java
public interface DocumentRepository extends JpaRepository<Document, String> {
    long deleteByIdAndOwnerId(String id, String ownerId);
}
```

## Explanation

The original code performs a sensitive action (document deletion) on behalf of an authenticated user without verifying the user has permission to delete that specific document. An attacker with login credentials can delete any document in the system by guessing or iterating document IDs.

Option 1 adds method-level authorization using Spring Security's `@PreAuthorize` annotation with a SpEL expression that calls a security bean to verify ownership before the endpoint executes. The bean loads the document and confirms the authenticated user (from `authentication.name`) is the owner.

Option 2 scopes the repository query itself to delete only when both the ID and owner match, so an attacker's request for a document they don't own results in a 404 (not found) rather than a 403 (forbidden), avoiding an enumeration oracle that reveals which documents exist.

Both approaches satisfy the CWE-862 remediation guidance: they check authorization at the service entry point and verify the caller has a granted relationship to the specific resource before executing the sensitive action.

## Behaviour changes

**Option 1 changes:**
- Adds a new `@PreAuthorize` annotation that enforces authorization before the method runs.
- A `DocumentSecurity` bean must exist and be available in the Spring context for the SpEL expression to resolve.
- Unauthorized requests from authenticated users receive a 403 Forbidden response instead of deleting the document.
- The response status changes for requests targeting documents the caller does not own: previously a 204 (success), now 403 (forbidden).

**Option 2 changes:**
- Adds `@AuthenticationPrincipal UserDetails userDetails` parameter to extract the authenticated username from the security context.
- The repository method `deleteByIdAndOwnerId` returns a count (long) indicating how many rows were deleted; zero deletion means the document doesn't exist or doesn't belong to the caller.
- Unauthorized requests receive a 404 Not Found response (indistinguishable from "document does not exist") rather than 403, preventing enumeration of document IDs.
- The response status changes for requests targeting documents the caller does not own: previously a 204 (success), now 404 (not found).
