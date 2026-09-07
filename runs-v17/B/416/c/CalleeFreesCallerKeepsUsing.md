## Verdict

Use-after-free confirmed. The `validate_and_normalize()` function frees the `req` pointer on the error path (lines 30-31), but the caller continues to access `req->clientId` at line 69 after the return.

## Source

E:/Github/cwe-advisor/evals/cases/416/c/CalleeFreesCallerKeepsUsing/CalleeFreesCallerKeepsUsing.c

- **Allocation**: line 50 (`malloc(sizeof(*req))`)
- **Release**: line 31 (inside `validate_and_normalize()` on error path)
- **Use-after-free**: line 69 (`req->clientId` accessed after release)

The root cause is an ownership boundary violation: `validate_and_normalize()` takes responsibility for freeing `req` on its error path (documented at lines 16-18 and 28-29), but `process_request()` treats the return to still own `req` and attempts to log its `clientId` field.

## Fix

The fix establishes clear, single ownership: `process_request()` owns the request for its entire lifetime, from allocation through deallocation. `validate_and_normalize()` becomes a pure validator that does not free the request on any path.

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
 * This function validates the request but does not assume ownership
 * of req for cleanup: it returns an error code and leaves req intact
 * (including its fields and allocations) so the caller retains full
 * responsibility for freeing it.
 */
static int validate_and_normalize(struct Request *req)
{
    if (req == NULL) {
        return -1;
    }

    if (req->payload == NULL || req->payloadLen == 0 ||
        req->payloadLen > MAX_PAYLOAD) {
        /* Malformed request: return error without freeing req.
         * The caller remains the owner and must clean up. */
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
        /* validate_and_normalize() only validated; it did not free req.
         * req is still valid and owned by this function. */
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

The fix resolves the use-after-free by establishing a single, clear owner for the `req` allocation: `process_request()` allocates it and is solely responsible for freeing it. `validate_and_normalize()` is changed from a validator-with-cleanup function to a pure validator: it checks the request fields and performs in-place normalization, but returns without freeing anything.

This aligns with CWE-416 remediation guidance: "Give each allocation one owner and make release that owner's responsibility alone." By removing the cleanup logic from the callee and keeping it entirely in the caller, the ownership boundary becomes unambiguous. The caller can now safely access `req->clientId` for error logging after `validate_and_normalize()` returns an error code, because `req` has never been freed.

The documentation in `validate_and_normalize()` is updated to make this ownership contract explicit, preventing future confusion about which function is responsible for cleanup.

## Behaviour changes

**Normal path (success)**: Unchanged. On success, `process_request()` still frees both `req->payload` and `req` at lines 74-75.

**Error path (validation fails)**: The caller can now safely access `req` after a validation failure. Previously, the fprintf at line 69 was dereferencing a freed pointer. Now it accesses valid memory. The caller then frees both fields at lines 81-82 before returning the error code, instead of attempting to use an already-freed pointer.

**Semantics**: `validate_and_normalize()` no longer takes ownership on error. Its ownership semantics are now identical on all paths: it validates and normalizes in place, but does not free. The caller retains ownership regardless of the return code.
