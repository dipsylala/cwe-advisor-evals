## Verdict

Confirmed. `DocumentController.delete` accepts a caller-supplied `documentId` and deletes it via `DocumentService.delete` -> `DocumentRepository.deleteById` with no check that the authenticated caller owns (or is otherwise entitled to delete) that document. Any authenticated user can delete any other user's document simply by enumerating or guessing document IDs (an insecure direct object reference resulting in missing authorization).

## Source

- Sink: `DocumentRepository.deleteById(String documentId)` (`DocumentRepository.java:4`) - performs the actual deletion with no ownership/authorization check.
- Path: `documentId` arrives as a `@PathVariable` on `DocumentController.delete` (`DocumentController.java:16-17`), is passed unchanged into `DocumentService.delete` (`DocumentService.java:10`), and from there straight into `repository.deleteById` (`DocumentService.java:11`). No layer in this chain verifies that the requesting principal has any relationship to the document being deleted.

## Fix

### File: DocumentController.java

```java
package cases.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
    public ResponseEntity<Void> delete(@PathVariable String documentId, Authentication authentication) {
        service.delete(documentId, authentication.getName());
        return ResponseEntity.noContent().build();
    }
}
```

### File: DocumentService.java

```java
package cases.authorization;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public void delete(String documentId, String requesterId) {
        String ownerId = repository.findOwnerId(documentId);
        if (ownerId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (!ownerId.equals(requesterId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        repository.deleteById(documentId);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public String findOwnerId(String documentId) {
        return null;
    }

    public void deleteById(String documentId) {
    }
}
```

## Explanation

The missing authorization is fixed by resolving the document's owner before any delete happens and comparing it against the identity of the caller making the request, rather than trusting a client-supplied ID alone to authorize the action.

- `DocumentController` now takes the Spring Security `Authentication` for the request and passes the authenticated principal's identity (`authentication.getName()`) down to the service, instead of only forwarding the path variable. This makes "who is asking" available at the point where the authorization decision has to be made.
- `DocumentService.delete` looks up the document's owner first (`repository.findOwnerId`). If no document exists, it fails closed with `404 Not Found`. If the document exists but its owner does not match the requester, it fails closed with `403 Forbidden`. The repository's `deleteById` is only reached once ownership is confirmed, closing the IDOR: an attacker who knows or guesses another user's `documentId` can no longer delete it.
- `DocumentRepository` gains `findOwnerId`, the lookup the ownership check depends on; `deleteById` itself is unchanged, since the vulnerability was never in how the delete is performed but in the fact that nothing gated the call to it.
- The stated fix reuses the requester identity already carried in Spring Security's `Authentication` object rather than inventing a new mechanism, and the ownership check runs on every call to `delete`, so it cannot be bypassed by any caller of the service.
