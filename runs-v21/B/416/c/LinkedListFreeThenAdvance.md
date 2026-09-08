## Verdict

exploitable

## Source

The `head` parameter and the `node` pointer derived from it within the linked list traversal loop (lines 12-16).

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
        if (node->expired) {
            struct SessionNode *next = node->next;
            free(node);
            node = next;
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

## Explanation

The original code freed a node at line 15 and then immediately dereferenced it at line 16 by accessing `node->next`. This is a use-after-free vulnerability: the memory holding the node's structure, including its `next` pointer, has been returned to the allocator and may be reused or unmapped, causing reading of freed memory. The fix captures the next pointer *before* freeing the current node. A temporary variable `next` stores `node->next` before the `free()` call, and then `node` is advanced to `next` instead of attempting to dereference already-freed memory. This pattern (capture, free, advance) is the standard safe iteration for linked-list cleanup in C.

## Behaviour changes

None. The fix preserves the loop's control flow and data-flow semantics. The `next` pointer is captured before release and used afterward, maintaining the same iteration order and continuation logic. No arguments, returns, or side effects are altered beyond closing the use-after-free.
