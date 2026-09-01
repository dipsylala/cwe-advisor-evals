## Verdict

Confirmed: Missing Authorization. The controller method deletes a document by ID without checking whether the authenticated caller owns it.

## Source

The `@PathVariable String documentId` at DocumentController.java line 16 in the method signature:
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId)
```

The documentId is extracted directly from the URL path without validation against the caller's ownership.

## Fix

**Add method-level authorization to the controller:**

```java
@DeleteMapping("/api/documents/{documentId}")
@PreAuthorize("@documentSecurity.canDeleteDocument(#documentId, authentication.name)")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

**Create a `DocumentSecurity` bean** that the `@PreAuthorize` expression references:

```java
@Component("documentSecurity")
public class DocumentSecurity {
    private final DocumentRepository repository;

    public DocumentSecurity(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean canDeleteDocument(String documentId, String username) {
        // Load the document and verify the authenticated user owns it
        Document document = repository.findById(documentId);
        return document != null && document.getOwnerId().equals(username);
    }
}
```

**Ensure Spring Security method-level authorization is enabled** in your Spring Boot configuration or main application class:

```java
@EnableMethodSecurity
```

## Explanation

The fix adds resource-level authorization through method-level security. The `@PreAuthorize` annotation intercepts the method and uses SpEL to call a security bean before execution. The bean loads the document and verifies the caller's username matches the document's owner. If the check fails, Spring Security raises `AccessDeniedException`, which `ExceptionTranslationFilter` translates to a 403 response for authenticated callers.

The ownership check happens at the controller layer before any deletion logic runs. By scoping the authorization to the specific resource (not just a role check), any authenticated user lacking ownership is denied, while the document owner can proceed.

This pattern covers every sensitive operation on the resource: read, list, update, delete, export—once the bean's ownership logic is correct, all callers inherit it.

## Behaviour changes

- **Before**: Any authenticated user can delete any document by supplying an arbitrary documentId in the URL.
- **After**: Only the document owner can delete their own document. Unauthorized callers receive a 403 Forbidden response. An authenticated caller without ownership cannot proceed.
- **Testing**: Write a test that calls the endpoint as an authenticated user lacking ownership and asserts the response is 403, confirming the authorization check blocks the operation.
