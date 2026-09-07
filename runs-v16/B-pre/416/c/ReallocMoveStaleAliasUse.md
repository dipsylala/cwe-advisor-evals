## Verdict

Use-after-free confirmed. The pointer captured at line 32 before `realloc()` becomes stale if the allocation moves, then is dereferenced at line 48 to write the status byte into freed memory.

## Source

```c
void log_buffer_init(struct LogBuffer *list, size_t initial_capacity)
{
    list->data = malloc(initial_capacity);
    list->last_write_ptr = NULL;
    list->capacity = initial_capacity;
    list->length = 0;
}

int log_buffer_append(struct LogBuffer *list, const char *record, char status)
{
    /* Remember where this record will land before we possibly grow
     * the buffer, so the status byte can be patched in below without
     * recomputing the offset a second time. */
    list->last_write_ptr = list->data + list->length;  // LINE 32: captures stale pointer

    if (list->length + RECORD_SIZE > list->capacity) {
        size_t newCapacity = list->capacity * 2;
        char *data = realloc(list->data, newCapacity);
        if (data == NULL) {
            return -1;
        }
        list->data = data;  // may point to different address; old pointer now invalid
        list->capacity = newCapacity;
    }

    memcpy(list->data + list->length, record, RECORD_SIZE);
    list->length += RECORD_SIZE;

    /* SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement. */
    list->last_write_ptr[RECORD_SIZE - 1] = status;  // LINE 48: uses stale pointer after realloc

    return 0;
}
```

## Fix

Move the pointer capture to after `realloc()` completes, when `list->data` is guaranteed to be valid and the allocation is at its current address. Compute the pointer from the current `list->data` using the offset from the length at the time the record was written.

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

    /* Set the pointer to the most recently written record, after
     * ensuring realloc has completed and list->data is at its current address. */
    list->last_write_ptr = list->data + list->length - RECORD_SIZE;
    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}
```

## Explanation

The original code captured `list->last_write_ptr` as an alias to the record's location in the buffer before calling `realloc()`. If `realloc()` moves the allocation to a different address (which it may do, even if the new size is larger), the old pointer becomes an alias into freed memory. When line 48 dereferences that stale pointer to write the status byte, it writes into memory the allocator has already reclaimed.

The fix reorders operations to ensure `list->data` is updated by `realloc()` before any pointer derived from it is captured. This makes `list->last_write_ptr` a valid pointer into the current allocation. The pointer is now computed from `list->data + list->length - RECORD_SIZE`, which reflects the base address of the record just written after all allocation changes are complete.

## Behaviour changes

- The pointer `list->last_write_ptr` now always points into the current valid allocation, eliminating the use-after-free window between `realloc()` and the dereference at line 48.
- The struct field `list->last_write_ptr` is still updated to track the most recently written record, preserving the intended semantics.
- No change to the function signature, return value, or external contract. The function still appends a record and stamps the status byte in the same logical order; reordering the pointer capture moves it outside the unsafe window.
- The fix is compatible with multi-threaded access if the caller provides external synchronization; it does not introduce new races.
