## Verdict
Use After Free confirmed on line 16. The code frees a node and then immediately accesses its `next` pointer, reading freed memory.

## Source
Line 14-17 in `purge_expired_sessions()`:
```c
if (node->expired) {
    free(node);
    node = node->next;  // Line 16: Use after free
    continue;
}
```

The `node` pointer is freed on line 15. The dereference `node->next` on line 16 reads from the freed memory.

## Fix
Save the next pointer before freeing the current node:
```c
if (node->expired) {
    struct SessionNode *next = node->next;
    free(node);
    node = next;
    continue;
}
```

## Explanation
The vulnerability occurs because the code attempts to traverse a linked list while freeing nodes, but does not preserve the next pointer before deallocation. After `free(node)` executes, the memory is returned to the allocator and reading `node->next` constitutes use-after-free. The fix caches the next pointer before freeing, preserving the ability to advance the traversal safely.
