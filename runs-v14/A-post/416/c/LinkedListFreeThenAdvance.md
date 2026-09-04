## Verdict
The use-after-free on line 16 is real. After `free(node)` on line 15, the code dereferences the freed pointer via `node->next` on line 16, yielding undefined behavior.

## Source
```c
void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);
            node = node->next;  // Line 16: freed pointer dereferenced
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
        if (node->expired) {
            struct SessionNode *next = node->next;  // Save next pointer before freeing
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
The vulnerability occurs because the code frees `node` and then immediately accesses `node->next`. Once `free()` is called, the memory containing `node` and its `next` pointer is returned to the allocator and may be reused or corrupted. Dereferencing it produces undefined behavior.

The fix saves the `next` pointer to a local variable before calling `free()`. This allows the loop to safely advance to the next node without dereferencing freed memory.
