## Verdict
exploitable

## Source
Allocation at line 50 (`struct Request *req = malloc(sizeof(*req))`), with secondary allocation at line 57 (`req->payload = malloc(rawLen)`).

## Fix

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

    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() already freed req on this path; use the
         * clientId parameter instead of dereferencing the freed pointer. */
        fprintf(stderr, "request rejected for client %d (rc=%d)\n", clientId, rc);
        return rc;
    }

    /* req->payload has been normalized; hand off to the next stage. */
    free(req->payload);
    free(req);
    return 0;
}
```

## Explanation

The vulnerability occurs because `validate_and_normalize()` assumes ownership of `req` on the error path and frees it before returning (line 31 in the original), but the caller then dereferences the freed pointer at line 69 to access `req->clientId`. The fix avoids dereferencing the stale pointer by using the `clientId` parameter that is already in scope, which holds the same value that was assigned to `req->clientId` at line 55. This eliminates the use-after-free without changing the logged output or the function's behavior.

## Behaviour changes

The fix replaces `req->clientId` with the `clientId` parameter in the fprintf call at line 69. Since `req->clientId` was assigned the value of the `clientId` parameter at line 55, both expressions produce identical output. The function's return value, error handling, and successful path remain unchanged. No new imports, libraries, or dependencies are introduced.

