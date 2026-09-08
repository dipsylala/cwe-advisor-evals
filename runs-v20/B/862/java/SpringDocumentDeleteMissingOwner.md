## Verdict

Confirmed. CWE-862 (Missing Authorization) at `DocumentController.java:16` (`@DeleteMapping("/api/documents/{documentId}")`). The endpoint deletes a document by client-supplied ID with no check that the caller owns or is otherwise entitled to that specific document.

## Source

`documentId` from the `@PathVariable` on `DELETE /api/documents/{documentId}` (`DocumentController.delete`).

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
        boolean deleted = service.delete(documentId, authentication.getName());
        if (!deleted) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.noContent().build();
    }
}
```

### File: DocumentService.java

```java
package cases.authorization;

public class DocumentService {
    private final DocumentRepository repository;

    public DocumentService(DocumentRepository repository) {
        this.repository = repository;
    }

    public boolean delete(String documentId, String ownerId) {
        return repository.deleteByIdAndOwnerId(documentId, ownerId);
    }
}
```

### File: DocumentRepository.java

```java
package cases.authorization;

public class DocumentRepository {
    public boolean deleteByIdAndOwnerId(String documentId, String ownerId) {
        return false;
    }
}
```

## Explanation

The call chain (`DocumentController.delete` -> `DocumentService.delete` -> `DocumentRepository.deleteById`) took only the path-supplied `documentId` and deleted it unconditionally: any authenticated caller could delete any document by guessing or enumerating IDs, with no check that the caller owns it. Per the CWE-862 Java guidance, an object-level ownership check on a guessable identifier should be enforced by scoping the lookup/mutation itself (`WHERE id = ? AND owner_id = ?`) rather than by a role annotation, since a role check alone would prove the caller is a valid user but nothing about whether they own this particular document.

The fix threads the caller's identity from the request into the delete path: the controller takes the Spring Security `Authentication` for the request and passes its principal name as `ownerId` down to the service and then the repository, which now deletes only where `id` and `owner_id` both match. The repository body is unchanged in effect from the original (still a stub with no persistence logic), but its contract changes from "delete unconditionally, return nothing" to "delete only the caller's own row, report whether a matching row existed" - which is exactly the scoped-query pattern the guidance prescribes for a guessable resource identifier, and it is what lets the controller distinguish "not yours" / "does not exist" from a successful delete without leaking which case occurred.

The controller now returns 404 when no row matched (not owned, or does not exist) and 204 only on an actual delete, matching the root guidance's direction that an object-level ownership check on a guessable ID should answer 404 identically for both cases rather than 403 (which would confirm the record exists to a caller who does not own it).

**Verification performed**: `Authentication` (`org.springframework.security.core.Authentication`) is a standard Spring Security interface; `getName()` is its documented accessor for the caller's principal name. `ResponseEntity.notFound()` is an existing static factory on the type already imported in this file, used identically to the pre-existing `ResponseEntity.noContent()` call. No new dependency is introduced. I copied the three fixed files to a scratch directory outside the repository, added minimal local stand-ins for the two Spring types used only by signature (`ResponseEntity`, `Authentication`) since the real Spring jars are not on this sandbox's classpath, and ran `javac` against the result - it compiled with no errors or warnings, confirming every signature (constructor calls, method calls, return types) lines up between the three files.

## Behaviour changes

- **Requires an authenticated caller**: the endpoint now needs a non-null `Authentication` for the request. I assumed - consistent with the Java guidance's description of this exact pattern ("secured only by the global authentication filter") - that the wider application already authenticates every request before it reaches the controller (e.g. a `SecurityFilterChain` with `.anyRequest().authenticated()|`), since none of the three files in this call chain configure authentication themselves. If that assumption is wrong and this endpoint can currently be reached unauthenticated, `authentication` will be `null` and `getName()` will throw; a `SecurityFilterChain`/entry-point configuration outside this call chain needs to guarantee an authenticated principal reaches this method.
- **Response code on a non-owned or nonexistent document changes from 204 to 404**: previously `delete` always returned 204 No Content regardless of whether the document existed or belonged to the caller. It now returns 404 Not Found in both of those cases, and 204 only when the caller's own document was actually deleted. This is the intended remediation (root guidance: an ownership check on a guessable identifier should scope the lookup and return 404 identically for "not yours" and "does not exist"), not incidental.
- **Repository/service signatures changed**: `DocumentRepository.deleteById(String)` (void) became `deleteByIdAndOwnerId(String, String)` (boolean), and `DocumentService.delete(String)` (void) became `delete(String, String)` (boolean). Any other caller of these two methods elsewhere in the real application (not present in this three-file excerpt) would need the same update.
