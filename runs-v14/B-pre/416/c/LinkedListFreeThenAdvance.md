## Verdict

Use-after-free confirmed at line 16. The code calls `free(node)` at line 15, then dereferences the freed pointer to access `node->next` at line 16. This is a classic linked-list traversal defect where the iterator is freed before advancing to the next node.

## Source

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);
            node = node->next;  // Use-after-free: dereferencing freed node
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

At line 15, `free(node)` releases the memory. At line 16, `node->next` dereferences the freed allocation to obtain the next pointer.

## Fix

Save the next pointer before freeing the current node:

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            struct SessionNode *next = node->next;  // Capture next before free
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

When iterating a linked list and freeing nodes, the next pointer must be captured before the current node is released. After `free(node)`, the memory is returned to the allocator and the pointer becomes invalid. Any subsequent dereference reads from deallocated memory, which may have been reused for an unrelated object, causing data corruption or crashes. The fix introduces a temporary variable `next` that holds `node->next` before the free, then advances the iterator using this saved value. This pattern—capture then free—is the standard safe way to walk and delete a linked list in C.

## Behaviour changes

**Before**: The function would crash or exhibit undefined behavior when dereferencing the freed node.

**After**: The function safely traverses and frees the list. Each freed node's next pointer is captured before release, and iteration continues using only live pointers. The function behavior remains the same—expired sessions are removed and non-expired ones are refreshed—but without memory safety violations.
