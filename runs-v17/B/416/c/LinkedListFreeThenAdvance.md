## Verdict
exploitable

## Source
The `node` pointer in the linked-list iteration (line 12-13), advancing through `node = node->next` assignments (lines 16, 21).

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
The original code freed `node` on line 15, then immediately accessed the freed memory through `node->next` on line 16 to advance the iteration. This is a use-after-free: once `free(node)` returns, that memory block is returned to the allocator and may be reused, rewritten, or unmapped. Dereferencing `node->next` reads from memory the program no longer owns. The fix captures `node->next` into a local variable before the `free()` call, then uses the saved pointer to advance. This satisfies the linked-list iteration pattern described in the C-specific guidance and eliminates the access to freed memory.

## Behaviour changes
none
