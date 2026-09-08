## Verdict

Exploitable. CWE-416 (Use After Free), confirmed at `LinkedListFreeThenAdvance.c:16`.

## Source

`head`, the `struct SessionNode *` linked-list handle passed into `purge_expired_sessions()`. Each node's `expired` flag and `next` pointer are read directly off nodes reachable from `head` as the loop walks the list; no validation or copy intervenes before the sink.

## Fix

The sink is `node = node->next;` on line 16, immediately after `free(node)` on line 15: the traversal reads `node->next` through the pointer it just released, dereferencing freed memory to decide where to go next. The struct's own `next` field is the only value that let the walk continue, and freeing the node destroys the caller's only remaining way to reach it - the fix has to capture that field before the release, not after.

Single-owner rule applies: each node is owned by its position in the list until traversal moves past it, and release must happen only after nothing further needs to read the node. Capturing `node->next` into a local before `free()` gives the loop a value it obtained while the node was still live, so the subsequent advance no longer touches freed memory. No new API, library, or ownership-transfer path is introduced; this is a same-file, same-function edit.

### File: LinkedListFreeThenAdvance.c

```c
#include <stdlib.h>

struct SessionNode {
    int session_id;
    int expired;
    struct SessionNode *next;
};

void refresh_session(int session_id);

void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        struct SessionNode *next = node->next;
        if (node->expired) {
            free(node);
            node = next;
            continue;
        }

        refresh_session(node->session_id);
        node = next;
    }
}
```

## Explanation

The loop previously read `node->next` after calling `free(node)` on the same iteration, dereferencing a pointer into memory the allocator was free to reuse - a textbook use-after-free that can corrupt the list traversal or crash the process depending on what occupies the freed block afterward. The fix captures `next = node->next` at the top of each iteration, before any possible free, and uses that saved value (`next`) instead of re-reading through `node` on both the expired and non-expired branches. This mirrors the CWE-416 C guidance's rule for list traversal: capture `node->next` before freeing `node`. The non-expired branch's `node = node->next` was also changed to `node = next` for consistency and because `node` is still valid there in either case; this is not a behavior change, only a use of the same value already computed that iteration.

## Behaviour changes

- Added local variable `next` to hold `node->next`, read once per iteration before the conditional free. This is the fix itself, not incidental.
- Non-expired branch changed from `node = node->next` to `node = next`: same value, since `node` is not freed on that branch; changed only to avoid a second, now-redundant dereference and to keep both branches using the single captured value. No functional difference.
- No change to `refresh_session()` calls, iteration order, or which nodes get freed - expired nodes are still freed exactly once, in the same order, and non-expired nodes still get `refresh_session()` called exactly as before.
- The function still does not null out the caller's `head` pointer or any external reference to a freed node; if the caller retains its own copy of `head` or any interior pointer into the list, that is unchanged from the original code's behavior and is outside this function's contract (the finding was scoped to the intra-function traversal-after-free at line 16).

## Verification

No C compiler (`gcc`, `clang`, `cc`) was available in the environment to compile-check the fix; this was confirmed by attempting `gcc` and finding it not on PATH. Verification was done by manual review: the only new identifier introduced is the local variable `next`, declared and used within the same function, no new includes, calls, or external symbols; every existing call (`free()`, `refresh_session()`) keeps its original argument. The corrected control flow was traced by hand for both the expired-node path (free then advance via the pre-captured `next`) and the non-expired path (refresh then advance via `next`), confirming the loop terminates the same way (when `node` becomes `NULL`) and visits the same sequence of nodes as the original, unmodified version.
