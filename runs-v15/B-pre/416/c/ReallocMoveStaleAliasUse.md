## Verdict
Exploitable

## Source
The initial computation of `list->last_write_ptr` at line 32 (`list->last_write_ptr = list->data + list->length;`), which captures a pointer to a location within the growable buffer before checking if the buffer will be reallocated.

## Fix
Replace the unsafe pattern of caching a pointer before realloc with a pattern that saves the offset and recalculates the pointer after all size changes are complete.

**Vulnerable code (lines 27-51):**
```c
int log_buffer_append(struct LogBuffer *list, const char *record, char status)
{
    /* Remember where this record will land before we possibly grow
     * the buffer, so the status byte can be patched in below without
     * recomputing the offset a second time. */
    list->last_write_ptr = list->data + list->length;

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

    /* SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement. */
    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}
```

**Fixed code:**
```c
int log_buffer_append(struct LogBuffer *list, const char *record, char status)
{
    /* Save the offset where this record will land, not the pointer, to ensure
     * it remains valid if the buffer is reallocated. */
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

    /* Now safe: recalculate the pointer after any reallocation. */
    list->last_write_ptr = list->data + write_offset;
    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}
```

## Explanation
The vulnerability stems from computing a pointer (`list->last_write_ptr = list->data + list->length`) before determining whether the underlying buffer will be reallocated. If `realloc()` moves the buffer to a new memory address (lines 34-42), the cached pointer becomes stale. The subsequent dereference at line 48 then accesses memory through an invalid pointer, potentially reading or writing into a freed block or memory now allocated for another object.

The fix eliminates the stale pointer by saving only the offset (`write_offset = list->length`) before the reallocation, then recalculating the valid pointer after all size changes are complete. This ensures that `list->last_write_ptr` always references the correct location within the current buffer, regardless of whether `realloc()` moved it. The pattern follows C best practices for safe reallocation: never retain a pointer across a `realloc()` call on the same allocation; instead, preserve the logical location (offset) and recompute the pointer afterward.

## Behaviour changes
None. The fix preserves the original semantics: `list->last_write_ptr` continues to reference the most recently written record, and the status byte is still written to its final position. The only change is the timing of when the pointer is calculated—after the buffer is stable rather than before a potential reallocation.
