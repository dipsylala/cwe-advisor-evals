## Verdict

Confirmed Use After Free (CWE-416) on line 69. The function `validate_and_normalize()` frees the `req` structure when validation fails (line 31), but the caller continues to dereference the freed pointer at line 69.

## Source

The vulnerability exists in the ownership contract between `validate_and_normalize()` and its caller. The callee assumes ownership of `req` on the error path and frees it, but the caller does not know about this transfer and attempts to access `req->clientId` after the function returns a nonzero error code, when `req` is already freed.

## Fix

Store the `clientId` before calling `validate_and_normalize()`, so that if the function frees `req`, we can still log the client ID without dereferencing freed memory:

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
        /* Store clientId before the call to avoid dereferencing freed memory. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", clientId, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

The change is on line 69: use the local `clientId` parameter instead of `req->clientId` when logging the error.

## Explanation

The root cause is a violation of the ownership contract. The function `validate_and_normalize()` documents that it "treats itself as the owner of req for cleanup purposes" on the error path and frees the entire structure. However, the caller in `process_request()` does not expect this and attempts to access fields in the freed memory after receiving an error code.

The fix preserves the documented contract of `validate_and_normalize()` (it still owns and frees `req` on error) but prevents the use-after-free by not accessing the freed structure. Since `clientId` is passed as a parameter and stored before validation, it remains valid and accessible even after `req` is freed.
