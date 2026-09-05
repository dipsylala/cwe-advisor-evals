## Verdict

Exploitable.

## Source

The loop iterates through a linked list starting at `head`. At line 15, `node` points to a `struct SessionNode` allocated on the heap.

## Fix

The vulnerability arises because `node->next` is accessed after `free(node)`, dereferencing memory that has already been released. The fix is to capture the next pointer before freeing the current node, as specified in the C-specific remediation guidance for linked-list traversals.

**Vulnerable code:**
```c
if (node->expired) {
    free(node);
    node = node->next;  // Use after free
    continue;
}
```

**Fixed code:**
```c
if (node->expired) {
    struct SessionNode *next = node->next;  // Capture next before free
    free(node);
    node = next;
    continue;
}
```

## Explanation

The fix captures `node->next` into a temporary variable before calling `free(node)`. After `free()` releases the memory, the freed pointer is no longer accessed; instead, the previously-captured `next` pointer is used to advance the loop. This eliminates the use-after-free by ensuring that no dereference occurs on `node` after it has been freed. The loop continues with the saved next pointer, which either points to the next live node or is `NULL`, causing the loop to terminate correctly. This pattern is the standard, safe approach for freeing nodes during linked-list traversal.

## Behaviour changes

None. The loop's control flow and iteration order remain identical. The only difference is that `node->next` is read before the free rather than after it, which preserves the intended value without changing the function's observable behaviour.
