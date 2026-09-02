## Verdict

Use-after-free confirmed. Line 16 dereferences `node->next` after `node` has been freed on line 15.

## Source

In `purge_expired_sessions()`, the linked-list traversal frees the current node but then immediately reads its `next` pointer to advance the loop:

```c
if (node->expired) {
    free(node);
    node = node->next;  // Use-after-free: node is freed, node->next is invalid
    continue;
}
```

## Fix

Capture the next pointer before freeing the current node:

```c
if (node->expired) {
    struct SessionNode *temp = node->next;
    free(node);
    node = temp;
    continue;
}
```

## Explanation

The fix saves `node->next` to a temporary variable before calling `free(node)`. Once freed, `node` and its contents are no longer accessible, but `temp` holds the address we need to continue traversal. Using `temp` instead of dereferencing the freed `node->next` eliminates the use-after-free. This is the standard safe pattern for linked-list iteration with in-place deletion.

## Behaviour changes

- No change to control flow or observable behavior.
- The loop now correctly traverses the entire list without undefined behavior.
- Memory safety is restored; no additional allocations or error handling required.

