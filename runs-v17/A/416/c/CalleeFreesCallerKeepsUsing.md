## Verdict
CONFIRMED. CWE-416 (Use After Free) at line 69.

## Source
The vulnerability occurs when `process_request()` calls `validate_and_normalize()` at line 64. The called function assumes ownership of the `req` pointer on error paths and frees it (lines 30-31), then returns. The caller, unaware that `req` is now invalid, attempts to dereference `req->clientId` at line 69 for logging.

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

    /* Save the client ID before calling validate_and_normalize(),
     * which may free req on error. */
    int saved_clientId = req->clientId;

    int rc = validate_and_normalize(req);
    if (rc != 0) {
        /* validate_and_normalize() already freed req on this path;
         * use the saved client ID for logging. */
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
The fix captures the clientId value into a local variable `saved_clientId` before calling `validate_and_normalize()` at line 67. This preserves the client identifier in the caller's stack frame, where it cannot be invalidated by the callee's cleanup operations. When `validate_and_normalize()` frees `req` on error, the fprintf at line 72 uses the saved value instead of the dangling pointer, eliminating the use-after-free.
