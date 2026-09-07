## Verdict

Real vulnerability confirmed. Use-after-free: `validate_and_normalize()` frees `req` on error (line 31), but the caller dereferences `req->clientId` immediately after at line 69.

## Source

Line 69 in `process_request()`:
```c
fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
```

This dereferences `req` after the callee `validate_and_normalize()` has already freed it on the error path.

## Fix

Change `validate_and_normalize()` to relinquish ownership: return an error code without freeing the structure. The caller, which allocated it, becomes solely responsible for cleanup.

**Fixed `validate_and_normalize()`:**
```c
static int validate_and_normalize(struct Request *req)
{
    if (req == NULL) {
        return -1;
    }

    if (req->payload == NULL || req->payloadLen == 0 ||
        req->payloadLen > MAX_PAYLOAD) {
        /* Malformed request. Return error without freeing; ownership
         * remains with the caller. */
        return -2;
    }

    /* Normalize payload in place (e.g. strip trailing whitespace). */
    while (req->payloadLen > 0 && req->payload[req->payloadLen - 1] == ' ') {
        req->payloadLen--;
    }

    return 0;
}
```

**Fixed `process_request()`:**
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
        /* validate_and_normalize() no longer owns req on error;
         * this function (the allocator) retains ownership and cleans up. */
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

The vulnerability arises from a violation of C ownership: `process_request()` allocates the `struct Request` at line 50, but `validate_and_normalize()` assumes ownership of it and frees it on error (line 31). When validation fails, the callee releases the memory and returns, yet the caller immediately dereferences the freed pointer to log `req->clientId`.

The fix enforces a single ownership model: the allocator (`process_request()`) is the sole owner and is responsible for cleanup on all paths. `validate_and_normalize()` now returns early on error without freeing the structure. The caller then safely accesses the error information (via the captured `clientId` and return code), cleans up both allocations, and returns. This eliminates the use-after-free because `req` is never dereferenced after it is freed.

The fix follows the principle that a function receiving a pointer as a parameter should not free it unless the function's contract explicitly states it assumes ownership; an implicit ownership transfer (happening only on error) is a common source of use-after-free defects in C.

## Behaviour changes

- `validate_and_normalize()` no longer frees its input on error; the caller must always clean up
- Error-path cleanup now happens in `process_request()` instead of being distributed across two functions
- The error log at line 69 now safely accesses `req->clientId` because `req` is still valid
