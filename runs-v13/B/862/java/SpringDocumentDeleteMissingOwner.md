## Verdict

Exploitable. The `delete` endpoint accepts a `documentId` path parameter and deletes the document without verifying that the authenticated caller is the owner. Any authenticated user can delete any document by guessing or enumerating identifiers.

## Source

HTTP DELETE request to `/api/documents/{documentId}` with attacker-controlled `documentId` path parameter. The `documentId` is passed directly through the service to the repository's `deleteById()` method with no ownership check.

## Fix

**Vulnerable Code** (DocumentController.java, line 16):

```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

**Fixed Code**:

```java
@DeleteMapping("/api/documents/{documentId}")
@PreAuthorize("@documentSecurity.canDeleteDocument(#documentId, authentication.principal.username)")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

**Supporting Bean** (DocumentSecurity.java, to be created):

```java
@Component
public class DocumentSecurity {
    private final DocumentRepository repository;

    public DocumentSecurity(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean canDeleteDocument(String documentId, String username) {
        Document document = repository.findById(documentId);
        return document != null && document.getOwnerId().equals(username);
    }
}
```

**Repository Update** (DocumentRepository.java):

```java
public class DocumentRepository {
    public Document findById(String documentId) {
        // Retrieve document from database by ID
    }

    public void deleteById(String documentId) {
    }
}
```

## Explanation

The fix adds method-level authorization using Spring Security's `@PreAuthorize` annotation with a SpEL expression that delegates to a security bean. The `DocumentSecurity.canDeleteDocument()` bean method loads the actual document from the repository and verifies that the authenticated username matches the document's owner before the deletion proceeds. If the ownership check fails, Spring Security raises `AccessDeniedException`, which is translated to an HTTP 403 by the security filter chain. This prevents unauthorized users from deleting documents they do not own. The fix follows Spring Security best practices by centralizing authorization logic in a dedicated security bean rather than embedding it inline, making the authorization rule reusable and testable.

## Behaviour changes

- The endpoint now requires method-level authorization to be enabled in the application (via `@EnableMethodSecurity` on a `@Configuration` class). Without this annotation, the `@PreAuthorize` check is ignored and the vulnerability remains unfixed.
- An unauthorized caller receives HTTP 403 Forbidden instead of HTTP 204 No Content. This is the correct distinction for an ownership-based authorization failure; for a guessable identifier, a 404 is more appropriate to avoid leaking the identifier's existence. If document IDs are guessable, modify the fix to use a scoped repository method `deleteByIdAndOwnerId(documentId, ownerId)` and catch the empty result as a 404 to prevent enumeration attacks.
- The fix requires that documents have an owner field (here `ownerId`) and that the `Document` entity exposes a `getOwnerId()` method. If the data model differs, adjust the ownership verification logic accordingly.
- Spring Security's method-level advice is proxy-based and does not protect calls made via `this` within the same bean, so ensure this method is not called from other methods on the same class without going through the proxy.
