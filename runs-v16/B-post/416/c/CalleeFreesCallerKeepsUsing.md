## Verdict

**CONFIRMED** - Use-after-free on line 69 accessing `req->clientId` after `validate_and_normalize()` has freed `req` on the error path.

## Source

Pointer `req` allocated at line 50 in `process_request()`. On success, the caller owns it; on error, ownership is transferred to `validate_and_normalize()` which frees it (lines 30-31) and returns non-zero. The caller's contract violation occurs at line 69 when `req->clientId` is accessed after an error return, dereferencing memory that was already freed.

## Fix

Capture `req->clientId` into a local variable before calling `validate_and_normalize()`. Use the captured value in the error-path fprintf instead of dereferencing the freed pointer:

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

    int clientId_captured = req->clientId;  /* Capture before validate_and_normalize may free req */
    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() already freed req on this path;
         * use the captured clientId instead of dereferencing the freed pointer. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", clientId_captured, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation

The vulnerability is an ownership contract violation between `validate_and_normalize()` and its caller. The callee explicitly takes ownership of `req` on the error path (documented in lines 16-18 and implemented in lines 30-31), freeing both the pointer and the struct. The caller then attempts to dereference `req->clientId` in the error-path log statement (line 69), accessing memory that has already been returned to the allocator. The fix respects the ownership contract by capturing the needed data (`clientId`) before the call that may free it, then using the captured value instead of dereferencing the freed struct. This follows the CWE-416 remediation principle: ensure no reference to a released allocation is ever dereferenced by giving each allocation a clear owner and respecting ownership boundaries.

## Behaviour changes

- Before fix: On validation error, the code attempts to log `req->clientId` through a freed pointer, resulting in undefined behavior (potential crash, data corruption, or silent memory read).
- After fix: On validation error, the code logs a previously captured `clientId` value from the stack, avoiding any dereference of freed memory.
- No change to normal success path (lines 73-76).
- No change to early-return error paths (lines 52, 60).
- No change to function signatures or external contracts.
