## Verdict
Confirmed use-after-free vulnerability. The code frees a node and immediately accesses its next pointer before the memory has been invalidated.

## Source
```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);           // line 15: freed
            node = node->next;    // line 16: use-after-free
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

## Fix
Store the next pointer before freeing the current node:

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            struct SessionNode *next_node = node->next;
            free(node);
            node = next_node;
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

## Explanation
The vulnerability occurs because `node->next` is accessed after `free(node)` deallocates the memory. At line 16, the pointer `node` points to freed memory; dereferencing it to access the `next` field is undefined behavior and constitutes a use-after-free.

The fix saves `node->next` to a temporary variable before calling `free()`, then uses the saved pointer to advance to the next node. This ensures no access to freed memory occurs.
