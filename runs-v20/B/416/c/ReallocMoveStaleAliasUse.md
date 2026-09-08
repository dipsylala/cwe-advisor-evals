## Verdict

exploitable

## Source

`log_buffer_append()`'s own logic: `list->last_write_ptr` is computed at line 32 as `list->data + list->length`, evaluated against the *pre-growth* backing allocation, before the capacity check that may call `realloc()`.

## Fix

Sink: line 48, `list->last_write_ptr[RECORD_SIZE - 1] = status;` in `log_buffer_append()`, `log_buffer.c`.

Data flow: `last_write_ptr` is cached at line 32 from `list->data` while `list->data` still points at the old, pre-growth allocation. If the append needs more room, line 36's `realloc()` may free that old block and return a different address, which is stored back into `list->data` at line 40 - but `last_write_ptr` is never updated, so it still holds the address inside the block `realloc()` may have just freed. `memcpy()` at line 44 correctly writes through the refreshed `list->data`, but the status-byte write at line 48 dereferences the stale `last_write_ptr`, reading/writing freed memory whenever `realloc()` moved the block (any `malloc` implementation may return a different address, and reliably will once the old block is fragmented or too small in place). This is a stale-alias use-after-free: one field (`data`) is refreshed after the reallocation, the other alias (`last_write_ptr`) is not, matching the C guidance in `cwe/416/c/INDEX.md` ("After `realloc()`, the old pointer is invalid whether or not the block moved" and "a copy held in a struct field ... is still dangling").

Sink contract: the statement returns nothing (assignment); it writes one byte at offset `RECORD_SIZE - 1` from the record's start into `list->data`'s backing storage, so the record's status byte is visible on any later read through `list->data`. Nothing is discarded. The implicit argument is which allocation `last_write_ptr` addresses - the code assumes it is still the current one. Failure behaviour is unaffected: `log_buffer_append()` still returns `-1` only on `realloc()` failure, unchanged.

Fix: compute `last_write_ptr` from `list->data` *after* the growth check has run, so it always addresses the current allocation, then write the status byte through it as before. This preserves the field's purpose (caching the offset of the just-written record) while removing the window where it can reference a freed block.

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
    if (list->length + RECORD_SIZE > list->capacity) {
        size_t newCapacity = list->capacity * 2;
        char *data = realloc(list->data, newCapacity);
        if (data == NULL) {
            return -1;
        }
        list->data = data;
        list->capacity = newCapacity;
    }

    /* Compute the write location only after any growth above, so it
     * always addresses the current backing allocation rather than one
     * that realloc() may have already moved or freed. */
    list->last_write_ptr = list->data + list->length;

    memcpy(list->data + list->length, record, RECORD_SIZE);
    list->length += RECORD_SIZE;

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

The only change is moving the assignment `list->last_write_ptr = list->data + list->length;` from before the `realloc()`-based growth check to immediately after it, right before the `memcpy()`. Everything else - the growth condition, the `realloc()` temporary-then-assign pattern (already correct in the original), the `memcpy()`, the length update, and the final status-byte write - is untouched. Because `last_write_ptr` is now derived from `list->data` after any reallocation has already updated it, the pointer always addresses the current, live allocation, so line 48 (unchanged) can no longer read or write through a pointer into a block `realloc()` freed. This closes the use-after-free while preserving the field's function of caching the offset of the record just written for the status-byte patch.

## Behaviour changes

None. The function's return value, its `-1` failure path, the bytes written to `list->data`, and the final value of `list->length` are identical to the original for every input; only the point at which `last_write_ptr` is computed changes, and that field is write-then-immediately-consumed within the same function call, not read by any caller in this file.

**Verification**: no C compiler (`gcc`/`cc`/`clang`) was reachable in this environment, so the fix was checked by hand: the function signature, includes, struct layout, and every other statement are byte-for-byte identical to the original; the moved assignment is the same expression as before, referencing only fields already in scope (`list->data`, `list->length`) with no new declarations, includes, or calls introduced; braces balance and the statement order (growth check -> compute pointer -> copy -> advance length -> stamp status -> return) type-checks the same way the original did.
