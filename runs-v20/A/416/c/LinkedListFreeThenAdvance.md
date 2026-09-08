## Verdict

Confirmed. `purge_expired_sessions` frees `node` and then dereferences the same freed pointer via `node->next` on the very next line, a use-after-free.

## Source

`node` originates from the caller-supplied `head` linked list traversal in `purge_expired_sessions` (`LinkedListFreeThenAdvance.c`, lines 11-13). Each node visited during the walk is a candidate for the flaw.

## Fix

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

The original loop calls `free(node)` at line 15 and then reads `node->next` at line 16 to advance the traversal. Once `free` returns, the memory backing `node` is no longer owned by this code; the allocator is free to reuse, poison, or unmap it at any time (and many debug/hardening allocators do so immediately). Reading `node->next` after the free is therefore a use-after-free: it may return garbage, return a stale-but-plausible pointer that quietly corrupts the rest of the traversal, or crash, depending on allocator behavior - all of which make the bug hard to catch by inspection or by non-adversarial testing.

The fix captures `next = node->next` before any freeing happens, mirroring the safe pattern already used implicitly by the non-expired branch (which reads `node->next` before advancing, since it never frees `node`). With `next` saved first, `free(node)` can safely discard `node` in either branch, and the loop advances using the pointer value that was captured while `node` was still valid memory. This preserves the original control flow and behavior for both expired and non-expired nodes, and requires no additional allocation, locking, or API change - only reordering when the pointer field is read relative to when the node is freed.

To verify: build a list containing at least one expired node followed by further nodes, run it under a poisoning/sanitizing allocator (e.g. AddressSanitizer or a debug heap that scribbles over freed memory), and confirm the walk completes and visits every node with no use-after-free report, where the original code would have triggered one as soon as an expired node's freed memory was overwritten before the `next` read.
