## Verdict
CONFIRMED - Use After Free (CWE-416)

## Source
The vulnerability occurs in the `purge_expired_sessions()` function. At line 15, the current node is freed with `free(node)`, but at line 16, the code immediately accesses `node->next` to advance the pointer. After `free()`, accessing any member of the freed structure is undefined behavior and constitutes a use-after-free vulnerability.

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
The fix saves the next pointer before freeing the current node. By storing `node->next` in a temporary variable `next` before calling `free(node)`, the code safely advances to the next node without accessing freed memory. This preserves the linked list traversal logic while eliminating the use-after-free vulnerability.
