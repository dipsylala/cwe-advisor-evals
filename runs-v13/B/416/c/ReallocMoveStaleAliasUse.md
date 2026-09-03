## Verdict

Exploitable. The code captures a pointer into the buffer (line 32), then performs a realloc that may free and relocate the buffer (lines 34-42), then dereferences the stale pointer (line 48). If realloc moves the allocation, the pointer from line 32 becomes a reference into freed memory.

## Source

Line 32: `list->last_write_ptr = list->data + list->length;`

The source captures a pointer into the backing allocation before a potential realloc.

## Sink

Line 48: `list->last_write_ptr[RECORD_SIZE - 1] = status;`

The sink dereferences the pointer. If realloc was called and moved the buffer, this dereference accesses freed memory.

## Fix

**Vulnerable code (lines 27–51):**

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
    /* Remember the offset where this record will land before we possibly grow
     * the buffer, so the status byte can be patched in below using the updated pointer. */
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

    /* Recalculate the pointer after potential realloc using the saved offset. */
    list->last_write_ptr = list->data + write_offset;
    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}
```

## Explanation

The fix captures the offset into the buffer (rather than the pointer itself) before realloc, then recalculates the pointer after realloc using the saved offset and the updated `list->data`. This ensures that if realloc moves the allocation to a new address, `last_write_ptr` is recomputed to point into the new buffer rather than the freed old one. The dereference at the sink now accesses valid memory within the reallocated buffer.

## Behaviour changes

None. The pointer `list->last_write_ptr` is still updated and dereferenced at the same logical points. The only change is that it is recalculated after realloc to point into the new buffer instead of being stale.
