## Verdict
CWE-416 (Use After Free) is confirmed. The pointer `list->last_write_ptr` is computed before a potential `realloc()` that may move the allocation, making the saved pointer stale when dereferenced.

## Source
```c
/* Line 32: Pointer saved before realloc */
list->last_write_ptr = list->data + list->length;

if (list->length + RECORD_SIZE > list->capacity) {
    size_t newCapacity = list->capacity * 2;
    char *data = realloc(list->data, newCapacity);
    if (data == NULL) {
        return -1;
    }
    list->data = data;  /* List->data may now point to a different address */
    list->capacity = newCapacity;
}

/* ... memcpy happens ... */

/* Line 48: Dereference of stale pointer */
list->last_write_ptr[RECORD_SIZE - 1] = status;
```

## Fix
Replace the pointer-based approach with an offset-based approach. Save the offset (not the pointer) before `realloc()`, then use that offset to compute the memory address after the allocation is finalized:

```c
int log_buffer_append(struct LogBuffer *list, const char *record, char status)
{
    /* Remember the offset (not pointer) where this record will land before
     * we possibly grow the buffer, so the status byte can be patched in
     * below without recomputing the offset a second time. */
    size_t write_offset = list->length;

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

    /* Use the saved offset with the valid data pointer */
    list->data[write_offset + RECORD_SIZE - 1] = status;

    return 0;
}
```

Optionally, if `struct LogBuffer` needs to maintain `last_write_ptr` for external use, update it only after the buffer is finalized: `list->last_write_ptr = list->data + write_offset;` before the final assignment.

## Explanation
The root cause is storing a derived pointer (`list->data + offset`) before a potentially heap-moving operation (`realloc`). If `realloc()` moves the allocation, the saved pointer becomes a dangling reference to the old (freed) memory location. The fix stores the **offset** instead, which is invariant under realloc, then recalculates the pointer using the new base address.

This pattern applies generally: when holding pointers into dynamically allocated memory that may be reallocated, store offsets or indices rather than pointers, and recalculate pointers only after the allocation is final.
