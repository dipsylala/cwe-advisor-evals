## Verdict

Confirmed. `process_request()` dereferences `req` (`req->clientId`) on line 69 after `validate_and_normalize()` has already freed it on the error path.

## Source

`req` is heap-allocated by `process_request()` at line 50 (`malloc(sizeof(*req))`) and passed by pointer to `validate_and_normalize()` at line 64.

## Fix

The malformed-input branch inside `validate_and_normalize()` (lines 26-33) frees both `req->payload` and `req` itself, then returns a nonzero error code. `process_request()` treats that return as ownership retained on the error path too: line 69 reads `req->clientId` after the object backing it has already been released, which is a use-after-free (and `req->clientId` is also freed-then-read, so this can crash or log corrupted/attacker-influenced data depending on allocator reuse).

The function contracts already document who owns `req` on which path (see the comments at lines 13-19 and 43-46): ownership transfers to `validate_and_normalize()` on error, and stays with `process_request()` on success. The bug is that `process_request()` still touches `req` after a call that may have taken ownership of it. The fix is to stop dereferencing `req` after that call can have freed it: capture the only field still needed for logging (`clientId`) into a local variable before the call, and log from that local variable instead of through `req` on the error path.

### File: CalleeFreesCallerKeepsUsing.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 4096

struct Request {
    int clientId;
    char *payload;
    size_t payloadLen;
};

/*
 * Validates and normalizes an incoming request in place.
 *
 * On malformed input this function treats itself as the owner of req
 * for cleanup purposes: it frees req and returns a nonzero error code.
 * On success it returns 0 and req remains valid and owned by the caller.
 */
static int validate_and_normalize(struct Request *req)
{
    if (req == NULL) {
        return -1;
    }

    if (req->payload == NULL || req->payloadLen == 0 ||
        req->payloadLen > MAX_PAYLOAD) {
        /* Malformed request: this function assumed ownership of req
         * on the error path, so it releases it before returning. */
        free(req->payload);
        free(req);
        return -2;
    }

    /* Normalize payload in place (e.g. strip trailing whitespace). */
    while (req->payloadLen > 0 && req->payload[req->payloadLen - 1] == ' ') {
        req->payloadLen--;
    }

    return 0;
}

/*
 * Processes one inbound request: allocates a request object, hands it to
 * validate_and_normalize() for validation, and on rejection logs the
 * client id before returning the error code to the caller.
 */
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

    /* validate_and_normalize() takes ownership of req and frees it on the
     * error path, so nothing about req can be read after this call unless
     * rc == 0. Capture the field needed for logging beforehand. */
    int loggedClientId = req->clientId;
    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() already freed req on this path; log
         * through the local copy instead of the now-dangling pointer. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", loggedClientId, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation

`clientId` is set once, right after allocation, and never changed by `validate_and_normalize()`, so caching it in a local variable before the call is safe on both the success and error paths and preserves the exact log output. On the error branch the code now only reads `loggedClientId` and `rc`, both plain locals, so no access to the freed `req` (or `req->payload`) remains. The success branch is unchanged: `req` is still valid there because `validate_and_normalize()` only frees it on the error path, matching the documented ownership contract, so `free(req->payload); free(req);` at the end still runs exactly once against a live object.
