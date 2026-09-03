## Verdict
Real Use After Free vulnerability. Line 69 accesses `req->clientId` after `validate_and_normalize()` has freed `req` on the error path.

## Source
The vulnerability occurs in the split ownership model between `process_request()` and `validate_and_normalize()`:

1. `process_request()` allocates the `struct Request` at line 50.
2. At line 64, `validate_and_normalize(req)` is called.
3. Inside `validate_and_normalize()`, when payload validation fails (line 26-33), the function frees both `req->payload` and `req` itself, returning an error code.
4. Back in `process_request()` at line 65-69, the code checks the error and attempts to log `req->clientId`, but `req` has already been freed.
5. Line 69 reads freed memory: `fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);`

The root cause is the undocumented ownership transfer: `validate_and_normalize()` takes ownership and frees the request on error, but the caller does not account for this when handling the error return code.

## Fix
Change `validate_and_normalize()` to never free the request structure. Let the caller retain full ownership:

```c
static int validate_and_normalize(struct Request *req)
{
    if (req == NULL) {
        return -1;
    }

    if (req->payload == NULL || req->payloadLen == 0 ||
        req->payloadLen > MAX_PAYLOAD) {
        /* Malformed request: validation failed, but do not free.
         * Ownership remains with the caller. */
        return -2;
    }

    /* Normalize payload in place (e.g. strip trailing whitespace). */
    while (req->payloadLen > 0 && req->payload[req->payloadLen - 1] == ' ') {
        req->payloadLen--;
    }

    return 0;
}
```

Update `process_request()` to always clean up:

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
        /* Validation failed; log the error, then clean up. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
        free(req->payload);
        free(req);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation
The fix restores a single, clear ownership model: the caller (`process_request()`) allocates and is responsible for cleanup, regardless of the validation outcome. This eliminates the Use After Free by ensuring `req` is not freed prematurely.

The root principle is that the allocator owns the lifetime. By removing the error-path freeing from `validate_and_normalize()`, the function becomes a pure validator: it checks the request and normalizes it if valid, but never deallocates. The caller always cleans up, making the ownership explicit and preventing the reading of freed memory.
