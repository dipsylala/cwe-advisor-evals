## Verdict

Use-after-free on line 16. The code frees `node` on line 15, then dereferences the freed memory via `node->next` on line 16.

## Source

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);
            node = node->next;  // USE AFTER FREE: node is freed above
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

## Fix

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        struct SessionNode *next = node->next;  // Save next pointer before freeing
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

The vulnerability occurs because `node->next` is accessed after `free(node)` deallocates the memory. To fix this, save the next node pointer to a temporary variable before freeing the current node. Use the saved pointer to advance the loop instead of dereferencing the freed memory.
