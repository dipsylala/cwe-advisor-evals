## Verdict

Confirmed. `DocumentController.delete` accepts a caller-supplied `documentId` and deletes it unconditionally, with no check that the requester owns, or is otherwise entitled to modify, that document. Any authenticated caller (or any caller at all, if this endpoint is not further gated by a security filter) can delete another user's document simply by supplying its ID.

## Source

- Sink: `DocumentRepository.deleteById(String documentId)` (`DocumentRepository.java:4`) - performs the delete with no ownership predicate.
- Reached via: `DocumentService.delete(String documentId)` (`DocumentService.java:10-12`), which forwards the ID straight to the repository with no authorization check in between.
- Entry point / source of the tainted identifier: `DocumentController.delete(@PathVariable String documentId)` (`DocumentController.java:16-20`) - `documentId` comes directly from the URL path, and the currently authenticated principal is never consulted or compared against the document's owner anywhere in the call chain.

This is a classic broken object-level authorization (BOLA/IDOR) gap: the endpoint authenticates who is calling (presumably, via the surrounding Spring Security filter chain) but never authorizes what they are allowed to act on.

## Fix

Thread the authenticated principal through to the point of the check, and verify ownership before the delete is allowed to happen, returning a generic not-found rather than leaking whether the document exists for another owner.

`DocumentController.java`:

```java
package cases.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
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
    public ResponseEntity<Void> delete(@PathVariable String documentId,
                                        @AuthenticationPrincipal UserDetails currentUser) {
        service.delete(documentId, currentUser.getUsername());
        return ResponseEntity.noContent().build();
    }
}
```

`DocumentService.java`:

```java
package cases.authorization;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId, String owner) {
        if (!repository.existsByIdAndOwner(documentId, owner)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        repository.deleteById(documentId);
    }
}
```

`DocumentRepository.java`:

```java
package cases.authorization;

public class DocumentRepository {
    public boolean existsByIdAndOwner(String documentId, String owner) {
        // Backed by a query such as
        // "select count(d) > 0 from Document d where d.id = :documentId and d.owner = :owner"
        // so a document that exists but belongs to someone else is indistinguishable
        // from one that does not exist at all.
        return false;
    }

    public void deleteById(String documentId) {
    }
}
```

## Explanation

The vulnerability is not in the delete call itself but in the missing authorization check upstream of it: the service trusted a caller-supplied identifier without confirming the currently authenticated user has any relationship to that resource. The fix closes the gap by making ownership part of the query used to gate the delete, rather than deleting first and checking second, and by extracting the principal from the security context (`@AuthenticationPrincipal`) instead of trusting anything client-supplied. Returning 404 for both "document does not exist" and "document exists but you don't own it" avoids turning the endpoint into an oracle that lets an attacker enumerate valid document IDs belonging to other users. This same pattern - checking `existsBy<Id>And<Owner>` (or loading the entity and comparing its owner field) before mutating - should be applied to any other read, update, or delete endpoint in this service that takes a resource ID from the client.
