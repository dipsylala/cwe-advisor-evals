## Verdict

Use After Free confirmed at line 69. The function `validate_and_normalize()` frees `req` on error paths (lines 30-31), but the caller `process_request()` continues to dereference `req->clientId` at line 69 after the function returns with an error code.

## Source

Lines 64-71 in `process_request()`:

```c
int rc = validate_and_normalize(req);
if (rc != 0) {
    /* validate_and_normalize() already freed req on this path; the
     * caller here is unaware and still logs through the pointer. */
    // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
    fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
    return rc;
}
```

And lines 28-33 in `validate_and_normalize()`:

```c
if (req->payload == NULL || req->payloadLen == 0 ||
    req->payloadLen > MAX_PAYLOAD) {
    /* Malformed request: this function assumed ownership of req
     * on the error path, so it releases it before returning. */
    free(req->payload);
    free(req);
    return -2;
}
```

## Fix

Change `validate_and_normalize()` to NOT take ownership of the request on the error path. Let the caller retain full responsibility for cleanup. Replace lines 28-33 with:

```c
if (req->payload == NULL || req->payloadLen == 0 ||
    req->payloadLen > MAX_PAYLOAD) {
    /* Malformed request: the caller retains ownership for cleanup. */
    return -2;
}
```

Then, in `process_request()`, ensure cleanup happens on all error paths. Replace lines 64-71 with:

```c
int rc = validate_and_normalize(req);
if (rc != 0) {
    fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
    free(req->payload);
    free(req);
    return rc;
}
```

## Explanation

The root cause is an ownership conflict: `validate_and_normalize()` claims ownership of `req` on failure (freeing both the payload and the structure itself), while `process_request()` still holds a pointer and expects to use it to log the error. This violates the single-ownership principle.

The fix clarifies ownership: `process_request()` allocates `req` and retains responsibility for cleanup in all cases. `validate_and_normalize()` operates on the request in-place but never takes ownership. This way:

1. The caller can safely dereference `req->clientId` to log the error before cleanup.
2. The caller controls all cleanup in a single place.
3. The responsibility model is clear and static throughout the call chain.
