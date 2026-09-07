## Verdict

exploitable

## Source

Allocation: Line 19 in `log_buffer_init()` via `malloc()`, or line 36 in `log_buffer_append()` via `realloc()`.
Saved pointer: Line 32 assigns `list->last_write_ptr = list->data + list->length` before a potential realloc.
Sink: Line 48 dereferences `list->last_write_ptr[RECORD_SIZE - 1]` after the buffer may have been moved by realloc.

Data flow: `list->data` is allocated, reallocated (line 36), which may move the allocation. The old address saved at line 32 becomes invalid. Dereferencing that invalid pointer at line 48 reads from freed memory.

## Fix

**Vulnerable code:**
```c
void log_buffer_append(struct LogBuffer *list, const char *record, char status)
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
void log_buffer_append(struct LogBuffer *list, const char *record, char status)
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

    /* Write the status byte to the last byte of the record just written.
     * Calculate the position directly from the current buffer state rather
     * than using a saved pointer that may have been invalidated by realloc. */
    list->data[list->length - 1] = status;

    return 0;
}
```

## Explanation

The vulnerability arises because `last_write_ptr` is assigned at line 32 before the buffer may be grown and moved by `realloc()` at line 36. After `realloc()` moves the allocation to a new address, the saved pointer still references the old (now freed) memory. When the code dereferences that stale pointer at line 48, it accesses freed memory—a use-after-free. The fix eliminates the saved pointer entirely and instead calculates the target address directly at the point of use, using `list->data + list->length - 1`. Since `list->data` is always updated to point to the current buffer after any realloc, and `list->length` reflects the current write position plus the size of the record just written, this calculation is always valid.

## Behaviour changes

The struct field `list->last_write_ptr` is no longer written at line 32 of `log_buffer_append()`. Its value is still maintained by `log_buffer_free()` (line 57), and the initialization in `log_buffer_init()` (line 20) sets it to NULL. Since the fixed code does not use `last_write_ptr` within `log_buffer_append()`, this field is dead in that function; it may be retained elsewhere in the codebase or in the public struct definition, so it is left in place. The final effect on behavior is nil: the same byte in the buffer receives the status value, calculated fresh from the current buffer pointer and length rather than from a stale saved address.
