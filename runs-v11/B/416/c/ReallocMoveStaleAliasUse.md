## Verdict

**Real issue confirmed.** Use-after-free via stale pointer to reallocated memory.

## Source

Line 32 caches a pointer to the buffer position:
```c
list->last_write_ptr = list->data + list->length;
```

This pointer is saved *before* checking whether the buffer needs to grow.

## Fix

Move the pointer cache to *after* the realloc block. This ensures `last_write_ptr` always points into the current valid allocation:

```c
int log_buffer_append(struct LogBuffer *list, const char *record, char status)
{
    if (list->length + RECORD_SIZE > list->capacity) {
        size_t newCapacity = list->capacity * 2;
        char *data = realloc(list->data, newCapacity);
        if (data == NULL) {
            return -1;
        }
        list->data = data;
        list->capacity = newCapacity;
    }

    memcpy(list->data + list->length, record, RECORD_SIZE);
    list->length += RECORD_SIZE;

    /* Cache pointer only after realloc, so it points to current valid buffer */
    list->last_write_ptr = list->data + list->length - RECORD_SIZE;

    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}
```

## Explanation

When `realloc()` moves the allocation to a new address, all old pointers into that buffer become invalid. The original code cached the pointer at line 32 before the realloc check, then dereferenced it at line 48. If realloc moved the block between those lines, `last_write_ptr` pointed into freed memory.

The fix defers the pointer cache until after the realloc block completes. At that point, `list->data` is guaranteed to point to the current valid allocation. The pointer is calculated as `list->data + list->length - RECORD_SIZE` because we want to point to the record we just wrote (which starts at `list->length - RECORD_SIZE` after the memcpy and length increment).

## Behaviour changes

- The record's status byte is still written to the same logical record position (the one most recently written).
- No functional change; the fix only ensures the pointer is always valid.
- The function's contract and return value remain unchanged.
