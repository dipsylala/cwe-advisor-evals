## Verdict

- **cwe_id**: CWE-416 (Use After Free)
- **location**: `CalleeFreesCallerKeepsUsing.c`, line 69 (`fprintf(stderr, "request rejected for client %d (rc=%d)\n", req->clientId, rc);`)
- **verdict**: exploitable
- **confidence**: high

## Source

- **source**: `req`, allocated with `malloc(sizeof(*req))` in `process_request()` (line 50); `req->payload` allocated with `malloc(rawLen)` (line 57) and filled from the caller-supplied `rawPayload`/`rawLen`.
- **call chain**: `process_request()` calls `validate_and_normalize(req)` (line 64). On the malformed-input branch, `validate_and_normalize()` calls `free(req->payload)` then `free(req)` (lines 30-31) and returns `-2`. Control returns to `process_request()`, which checks `rc != 0` (line 65) and, believing it still owns `req`, dereferences the freed pointer at `req->clientId` in the `fprintf` on line 69 - the sink.
- **sink contract**: `validate_and_normalize()` returns an `int` status; the comment above it (lines 13-18) documents an ownership hand-off - on error it "assumes ownership of req for cleanup purposes" and frees it, but on success `req` remains owned by the caller. `process_request()`'s error branch does not follow that documented contract: it treats `req` as still live regardless of `rc`, so it logs through the pointer and would double-free it were the `free`/`return` at lines 74-75 reached instead (it is not, because of the early `return rc` - but the log statement at line 69 is a genuine use-after-free). The finding is a real violation of the documented split-ownership contract, matching the C guidance's "pointer freed inside a callee while the caller keeps using it" pattern (`cwe/416/c/INDEX.md`).

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
 * This function never takes ownership of req: on both the success and
 * error paths, req (and req->payload) remain allocated and owned by the
 * caller, which is responsible for freeing them exactly once.
 */
static int validate_and_normalize(struct Request *req)
{
    if (req == NULL) {
        return -1;
    }

    if (req->payload == NULL || req->payloadLen == 0 ||
        req->payloadLen > MAX_PAYLOAD) {
        /* Malformed request: report the error but leave req intact.
         * The caller still owns req and is responsible for freeing it. */
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
        /* validate_and_normalize() no longer frees req on this path;
         * process_request() remains the sole owner and is responsible
         * for freeing req and req->payload exactly once, after it is
         * done using them. */
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

The defect was a split-ownership contract: `validate_and_normalize()` freed `req` (and `req->payload`) on its error return, while `process_request()`'s error branch assumed `req` was still live and dereferenced it in the `fprintf` log call - a classic callee-frees/caller-keeps-using use-after-free. The fix applies the C guidance's single-ownership principle directly: `validate_and_normalize()` is changed to never free `req`, on either the success or the error path, so it is purely a validation function with no ownership role. `process_request()`, which is the function that allocated `req` and `req->payload`, becomes their sole owner and is now responsible for freeing both in every return path - it already did this on success, and the error branch is changed to do the same, after the logging statement that needs the still-valid pointer. This removes the use-after-free at line 69 because `req` is never freed until after it has been fully used, and it introduces no double-free because each allocation is now freed exactly once, on exactly one path, by exactly one function.

## Behaviour changes

- `validate_and_normalize()` no longer calls `free(req->payload)` / `free(req)` on the malformed-input branch (previously lines 30-31). Reason: this is the ownership fix itself - the callee must not free memory it does not own.
- `process_request()`'s error branch (`rc != 0`) now calls `free(req->payload)` and `free(req)` after the `fprintf` log statement, before `return rc`. Reason: with the callee no longer freeing `req`, the caller (which allocated it) must free it exactly once on this path to avoid a memory leak; freeing after the log call preserves the log's use of `req->clientId`.
- The docstring comment above `validate_and_normalize()` was updated to state the new no-ownership contract, since the old comment documented the ownership hand-off that caused the bug. Reason: keeps the code's documented contract truthful; no behavioural effect.
- Return codes (`-1`, `-2`, `0`) and all logging output are unchanged; the success path is unchanged.
- No new functions, types, or external APIs were introduced - only `free()`, `malloc()`, `fprintf()`, `memcpy()`, all already present in the original file and all from the C standard library (`stdlib.h`, `stdio.h`, `string.h`, already included).
- **Verification**: no C compiler (gcc, clang, cl, tcc) was available in the environment to run a syntax check. The fix was verified by manual review: it adds no new symbols, imports, or signature changes; every `malloc`/`free` pair was traced and confirmed to execute exactly once per allocation on every return path (`req` allocation failure, `req->payload` allocation failure, validation-rejected, and success); and the previously-freed-then-used pointer at the line-69 sink is now dereferenced strictly before its single `free()` call.
