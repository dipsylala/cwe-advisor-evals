## Verdict

Exploitable. Confidence: high.

`DELETE /api/documents/{documentId}` deletes any document identified by an attacker-controlled path variable with no check that the authenticated caller owns that document. Any authenticated user can enumerate or guess `documentId` values and delete documents belonging to other users. This is CWE-862 (Missing Authorization) rather than CWE-306 (authentication itself may still be enforced upstream by the security filter chain, which is out of scope for this fixture) or CWE-863 (there is no ownership check present to be flawed - it is absent entirely).

## Source

Call chain (3 files):

- `DocumentController.delete(String documentId)` (`DocumentController.java:16-20`) - `@DeleteMapping("/api/documents/{documentId}")` binds the untrusted, guessable `documentId` path variable and forwards it unchanged.
- `DocumentService.delete(String documentId)` (`DocumentService.java:10-12`) - pass-through, adds no authorization logic.
- `DocumentRepository.deleteById(String documentId)` (`DocumentRepository.java:4-5`) - the sink. Deletes the record identified solely by `documentId`, with no clause scoping the deletion to the requesting caller.

Sink contract established before fixing:
- **Returns:** `void`; the controller has no signal to distinguish "deleted", "not found", or "not yours".
- **Discards:** any outcome information - a caller cannot tell whether the delete had any effect.
- **Arguments left implicit:** no caller/owner identity is passed at any layer.
- **Failure behaviour:** none defined in the stub; the controller always returns `204 No Content` regardless of whether a matching, owned record existed.

No check anywhere in the chain confirms the authenticated caller owns `documentId` before the delete executes, so the finding is exploitable as reported.

## Fix

No third-party library change is required; this is a code-level ownership check per `cwe/862/java/INDEX.md`, using a repository method scoped by owner (`findByIdAndOwnerId`/`deleteByIdAndOwnerId`) whose empty result becomes a 404, per that guidance's Key Principles.

**Vulnerable code**

`DocumentController.java`:
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId) {
    // No check that the authenticated caller owns documentId.
    service.delete(documentId);
    return ResponseEntity.noContent().build();
}
```

`DocumentService.java`:
```java
public void delete(String documentId) {
    repository.deleteById(documentId);
}
```

`DocumentRepository.java`:
```java
public void deleteById(String documentId) {
}
```

**Fixed code**

`DocumentController.java`:
```java
@DeleteMapping("/api/documents/{documentId}")
public ResponseEntity<Void> delete(@PathVariable String documentId, Authentication authentication) {
    boolean deleted = service.delete(documentId, authentication.getName());
    if (!deleted) {
        return ResponseEntity.notFound().build();
    }
    return ResponseEntity.noContent().build();
}
```
(add `import org.springframework.security.core.Authentication;`)

`DocumentService.java`:
```java
public boolean delete(String documentId, String ownerId) {
    return repository.deleteByIdAndOwnerId(documentId, ownerId);
}
```

`DocumentRepository.java`:
```java
public boolean deleteByIdAndOwnerId(String documentId, String ownerId) {
    // Scope the delete to a record that both matches documentId and is
    // owned by ownerId - do not delete on documentId alone. Returns
    // whether a matching, owned row was actually removed.
    return deleteWhereIdAndOwnerMatch(documentId, ownerId);
}
```
(`deleteWhereIdAndOwnerMatch` stands in for this stub's absent persistence layer - in a real repository this is a single scoped statement, e.g. a Spring Data JPA `deleteByIdAndOwnerId(String id, String ownerId)` derived query or `DELETE FROM documents WHERE id = ? AND owner_id = ?`, whose affected-row count becomes the returned boolean.)

## Explanation

The fix threads the authenticated caller's identity (`authentication.getName()`) from the controller down to the repository and scopes the delete to a record that matches both `documentId` and that identity, instead of `documentId` alone. This closes the missing-authorization gap: a caller can no longer delete a document merely by knowing or guessing its ID. The repository now reports whether a matching, owned row was actually deleted, and the controller turns a `false` result into `404 Not Found` - identical, in status and body, to what a nonexistent `documentId` would produce - so the endpoint does not leak which IDs exist to a caller who doesn't own them (per the guidance's enumeration-oracle principle for object-level ownership checks on guessable identifiers).

## Behaviour changes

- Controller method gains an `Authentication authentication` parameter - required to determine the caller's identity for the ownership check; supplied by Spring Security's argument resolver for any authenticated request, so no new input is exposed to the client.
- Response changes from unconditional `204 No Content` to `404 Not Found` when `documentId` does not exist or is not owned by the caller - this is the deny-by-default behavior the fix requires, not incidental; it also removes the "record exists but isn't yours" signal a `403` would leak.
- `DocumentService.delete` signature changes from `delete(String)` returning `void` to `delete(String, String)` returning `boolean` - the added parameter carries the owner identity into the scoped query, and the return value is needed so the controller can select 204 vs. 404.
- `DocumentRepository.deleteById` is renamed `deleteByIdAndOwnerId` and gains the `ownerId` parameter and a `boolean` return - required to perform the scoped delete and report whether a matching, owned row existed. The concrete scoped-query implementation is left to the real persistence layer, since this fixture's repository has no backing store to wire it to.
