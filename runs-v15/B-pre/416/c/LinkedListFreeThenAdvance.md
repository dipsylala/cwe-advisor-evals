## Verdict

Real issue. Use-after-free at line 16 where `node->next` is dereferenced after `free(node)` on line 15.

## Source

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);        // Line 15: node freed
            node = node->next; // Line 16: node dereferenced after free
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

The list-walking loop frees the current node but then immediately accesses `node->next` to advance through the iteration. After `free(node)`, the memory is returned to the allocator and may be reused for unrelated objects, making any dereference undefined behaviour.

## Fix

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            struct SessionNode *next = node->next; // Capture next pointer before free
            free(node);
            node = next;
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

Capture the `next` pointer before calling `free()`, then use the saved pointer to advance the iteration. This ensures no dereference occurs after the node is released.

## Explanation

The C guidance for CWE-416 explicitly addresses this pattern: "a linked-list traversal that frees while iterating" must "capture `node->next` before freeing `node`" to avoid use-after-free. The freed memory is returned to the allocator's free list; accessing it afterward reads from memory that may have been reallocated for another object. By saving `node->next` to a temporary variable before calling `free(node)`, the iteration safely advances using the saved pointer rather than attempting to dereference already-released memory.

## Behaviour changes

Functional behaviour is unchanged: the loop iterates and frees expired nodes identically to before. Memory safety is restored—the program no longer dereferences freed memory and will not corrupt reused allocations or trigger undefined behaviour when the freed block is reallocated.
