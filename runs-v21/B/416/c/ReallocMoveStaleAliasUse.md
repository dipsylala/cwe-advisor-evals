## Verdict

exploitable

## Source

`list->data` pointer allocation and reallocation at lines 19 and 36.

## Fix

### File: log_buffer.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Growable append-only log buffer. The caller repeatedly appends
 * fixed-size records; when the backing store runs out of room the
 * buffer is grown with realloc(). */
struct LogBuffer {
    char *data;            /* backing allocation */
    char *last_write_ptr;  /* pointer to the most recently written record */
    size_t capacity;       /* total bytes allocated */
    size_t length;         /* bytes currently used */
};

#define RECORD_SIZE 64

void log_buffer_init(struct LogBuffer *list, size_t initial_capacity)
{
    list->data = malloc(initial_capacity);
    list->last_write_ptr = NULL;
    list->capacity = initial_capacity;
    list->length = 0;
}

/* Append one fixed-size record, growing the buffer if needed, then
 * stamp a trailing status byte onto the record just written. */
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
        /* After realloc, list->data may have moved to a different address.
         * Recalculate list->last_write_ptr using the updated data pointer. */
        list->last_write_ptr = list->data + list->length;
    }

    memcpy(list->data + list->length, record, RECORD_SIZE);
    list->length += RECORD_SIZE;

    /* SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement. */
    list->last_write_ptr[RECORD_SIZE - 1] = status;

    return 0;
}

void log_buffer_free(struct LogBuffer *list)
{
    free(list->data);
    list->data = NULL;
    list->last_write_ptr = NULL;
    list->capacity = 0;
    list->length = 0;
}
```

## Explanation

The vulnerability arises because `last_write_ptr` is derived from `data` before the realloc at line 36. If realloc moves the buffer to a new address, the stale `last_write_ptr` still holds the old address (which is now freed memory). Although the memcpy correctly uses the updated `data` pointer, the dereference of `last_write_ptr` at the original line 48 accesses freed memory, allowing potential corruption or code execution. The fix recalculates `last_write_ptr` immediately after the realloc succeeds and `list->data` has been updated to point to the new location. This ensures that whether or not the realloc moved the buffer, `last_write_ptr` always references valid memory at the correct offset within the current allocation.

## Behaviour changes

None. The recalculation of `list->last_write_ptr` after the realloc preserves the original intent and contract: `last_write_ptr` points to the record that was just written, and the status byte is stamped into the correct location. No return values, discarded output, implicit parameters, or error handling change.
