## Verdict

Confirmed use-after-free at line 69. The function `validate_and_normalize()` frees the `req` structure on validation failure (line 31), but `process_request()` continues to dereference `req->clientId` in the fprintf call at line 69, after ownership has been transferred and the memory released.

## Source

```c
// Line 64-70 in process_request()
int rc = validate_and_normalize(req);
if (rc != 0) {
    /* validate_and_normalize() already freed req on this path; the
     * caller here is unaware and still logs through the pointer. */
    // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
    fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
    return rc;
}
```

## Fix

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

    // Capture clientId before calling validate_and_normalize(),
    // since that function may free req on the error path.
    int saved_clientId = req->clientId;
    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() already freed req on this path;
         * use the saved clientId value instead of dereferencing req. */
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

The vulnerability arises from a broken ownership contract: `validate_and_normalize()` assumes ownership of `req` and frees it on the error path (lines 30-31), but `process_request()` is unaware of this transfer and attempts to access `req->clientId` after the memory has been released. The fix captures the `clientId` value into a local variable before calling `validate_and_normalize()`, ensuring the fprintf call does not dereference a freed pointer. This preserves the documented behavior of `validate_and_normalize()` (which frees `req` on error) while preventing the use-after-free in the caller.

## Behaviour changes

- Line 68: Added `int saved_clientId = req->clientId;` to capture the client ID before the validation call
- Line 69: Changed `req->clientId` to `saved_clientId` in the fprintf to use the captured value instead of dereferencing the freed pointer
- No functional behavior change to the error return code or logging output; only the mechanism of obtaining clientId changes
