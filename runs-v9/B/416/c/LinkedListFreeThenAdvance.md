## Verdict

exploitable (confidence: high)

CWE-416, Use After Free, in `purge_expired_sessions` at `LinkedListFreeThenAdvance.c:16`.

## Source

`head`, the `struct SessionNode *` linked list passed into `purge_expired_sessions`. The traversal pointer `node` walks this list starting from `head`.

## Fix

Vulnerable code:

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);            // node's memory is released here
            node = node->next;     // use after free: reads node->next from freed memory
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
```

Fixed code:

```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            struct SessionNode *next = node->next;  // capture before release
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

At line 15, `free(node)` releases the node's allocation, but line 16 then dereferences `node->next` to obtain the next list element - a read from memory the function no longer owns. The allocator may have already returned the block to a free list or handed it to another allocation, so `node->next` can silently return a stale, reused, or corrupted value with no fault at this line. The fix saves `node->next` into a new local, `next`, before calling `free()`, so the traversal step no longer touches the freed block; `node` is then advanced from `next` instead. This is the standard "capture the link before releasing the node" pattern for freeing while iterating a singly linked list, and it removes the only access to `node` that occurs after its release.

## Behaviour changes

None. The sink (`free`) still receives the same pointer and its `void` return continues to be discarded as before. The loop still frees every expired node, still calls `refresh_session` on every non-expired node with the same `session_id` argument, and still terminates by walking to the same next node in the original list order - only the source of the "next" value moves from a post-free read to a pre-free capture, which does not change which node is visited next in a well-formed list.
