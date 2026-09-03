## Verdict

Use-after-free vulnerability confirmed at line 69.

## Source

The `validate_and_normalize()` function (lines 20-41) frees both `req->payload` and `req` on the error path (lines 30-31). It takes ownership of the allocation on error as documented in its contract (lines 16-18). The function returns an error code but does not signal to the caller that the pointer has been freed.

## Fix

**Vulnerable code:**
```c
int process_request(int clientId, const char *rawPayload, size_t rawLen)
{
    struct Request *req = malloc(sizeof(*req));
    if (req == NULL) {
        return -1;
    }

    req->clientId = clientId;
    req->payloadLen = rawLen;
    req->payload = malloc(rawLen);
    if (req->payload == NULL) {
        free(req);
        return -1;
    }
    memcpy(req->payload, rawPayload, rawLen);

    int rc = validate_and_normalize(req);
    if (rc != 0) {
        // PROBLEM: req has been freed by validate_and_normalize() on error,
        // but this code dereferences req->clientId (use-after-free).
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

**Fixed code:**
```c
int process_request(int clientId, const char *rawPayload, size_t rawLen)
{
    struct Request *req = malloc(sizeof(*req));
    if (req == NULL) {
        return -1;
    }

    req->clientId = clientId;
    req->payloadLen = rawLen;
    req->payload = malloc(rawLen);
    if (req->payload == NULL) {
        free(req);
        return -1;
    }
    memcpy(req->payload, rawPayload, rawLen);

    /* Save clientId before calling validate_and_normalize(),
     * since that function frees req on error and we need the ID to log. */
    int saved_clientId = req->clientId;
    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() has freed req on this path;
         * use the saved clientId instead of dereferencing the freed pointer. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", saved_clientId, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation

The vulnerability arises from a crossing-boundaries ownership problem: `validate_and_normalize()` assumes ownership of the `req` allocation on error (frees it) but the caller in `process_request()` remains unaware. When an error occurs, `req` is freed inside `validate_and_normalize()`, but the caller then tries to access `req->clientId`, reading from memory that has been deallocated.

The fix captures the `clientId` into a local variable before the call, so the information needed for error logging remains available as a fresh stack variable even if the heap allocation is freed. This preserves the error logging functionality while eliminating the use-after-free. The problematic ownership boundary - where a callee secretly frees what the caller still thinks it owns - is still present in `validate_and_normalize()`'s contract, but the caller is now protected by not depending on the freed memory.

## Behaviour changes

- When `validate_and_normalize()` returns an error, the error message still logs the client ID but now reads from `saved_clientId` (a local stack variable) instead of `req->clientId` (freed heap memory).
- The logged client ID remains correct because it was captured before the call.
- No change to the function's return value or success path; only the error-reporting path is modified.
- The program no longer dereferences freed memory on the error path.
