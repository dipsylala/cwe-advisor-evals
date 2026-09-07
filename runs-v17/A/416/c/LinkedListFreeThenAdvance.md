## Verdict
Use-after-free confirmed at line 16. The code frees a linked list node then immediately dereferences its `next` pointer.

## Source
```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);
            node = node->next;  // Line 16: use-after-free
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

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
            struct SessionNode *temp = node->next;
            free(node);
            node = temp;
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

## Explanation
The vulnerability occurs because `node->next` is accessed after `node` has been freed. When `free()` deallocates the memory block, any subsequent read from that memory is undefined behavior. The fix saves the next pointer to a temporary variable before freeing the current node, then advances using the saved pointer. This ensures we never read from freed memory.
