## Verdict

The use-after-free on line 69 is confirmed. `validate_and_normalize()` assumes ownership of `req` and frees it when returning an error code (lines 30-31), but the caller then dereferences `req->clientId` to log the error, accessing memory that has already been released.

## Source

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
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);
        return rc;
    }

    free(req->payload);
    free(req);
    return 0;
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

    int rc = validate_and_normalize(req);
    if (rc != 0) {
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", clientId, rc);
        return rc;
    }

    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation

The ownership contract between `process_request()` and `validate_and_normalize()` requires that when the validation function fails, it takes ownership of `req` for cleanup and releases it before returning. This means the caller must not access `req` after receiving a non-zero return code from `validate_and_normalize()`.

The fix is to use the `clientId` parameter that `process_request()` already holds rather than dereferencing `req->clientId` after the validation returns an error. The `clientId` value is available in the caller's scope and does not require accessing the freed struct.

This preserves the intended ownership semantics: the validation function owns cleanup on the error path, and the caller does not attempt to access the freed allocation.

## Behaviour changes

No functional behaviour changes. The error log continues to print the same information (client ID and return code), but now sources the client ID from the caller's own parameter rather than dereferencing freed memory. The fix eliminates the undefined behaviour without altering what happens on the success path or the error reporting path.
