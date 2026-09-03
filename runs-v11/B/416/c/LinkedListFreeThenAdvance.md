## Verdict

exploitable

## Source

Heap-allocated `struct SessionNode` at the head of the linked list, iterated and freed in `purge_expired_sessions()`.

## Fix

**Vulnerable code (lines 14-18):**
```c
if (node->expired) {
    free(node);
    node = node->next;
    continue;
}
```

**Fixed code:**
```c
if (node->expired) {
    struct SessionNode *next = node->next;
    free(node);
    node = next;
    continue;
}
```

## Explanation

The vulnerability occurs because the code attempts to dereference `node->next` immediately after calling `free(node)`, which releases the memory. After the free, `node` points to memory that has been returned to the allocator and may have been reallocated for other purposes, causing undefined behavior. The fix captures the next pointer into a temporary variable before the free occurs, making the subsequent access safe. This pattern is the correct way to iterate and free nodes in a linked list: you must save the successor before releasing the current node, since dereferencing a freed pointer—even to extract a field—is undefined behavior.

## Behaviour changes

none
