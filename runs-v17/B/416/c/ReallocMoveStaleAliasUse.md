## Verdict

The finding is valid. Line 48 dereferences a stale pointer after a potential `realloc()` that may have moved the buffer. The pointer stored at line 32 becomes invalid if `realloc()` relocates the memory block.

## Source

The vulnerable pattern involves saving a pointer into a dynamically allocated buffer before a `realloc()` call, then using that saved pointer after the realloc. When `realloc()` moves the buffer to a new address (which it typically does when growing), the saved pointer references freed/reallocated memory.

**Vulnerable code (lines 32-48):**
- Line 32: `list->last_write_ptr = list->data + list->length;` saves a pointer before potential realloc
- Lines 34-41: `realloc()` may move the buffer to a new address
- Line 48: `list->last_write_ptr[RECORD_SIZE - 1] = status;` dereferences the stale pointer

The stale pointer is used even if realloc did not move the buffer, which means the code silently fails when growth is needed. The use-after-free window opens precisely when the growth condition triggers—the exact scenario the buffer is designed to handle.

## Fix

Replace pointer-based tracking with offset-based tracking. Save the offset (index into the buffer) before the potential realloc, then compute the correct pointer from the current `list->data` and the saved offset after realloc completes.

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
    /* Remember the offset of where this record will land before we possibly grow
     * the buffer, so the status byte can be patched in below without
     * recomputing the offset a second time. */
    size_t record_offset = list->length;

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

    /* Write the status byte at the correct offset in the (possibly reallocated) buffer. */
    list->data[record_offset + RECORD_SIZE - 1] = status;
    list->last_write_ptr = list->data + record_offset;

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

The vulnerability arises because `list->last_write_ptr` is set to an absolute address before the realloc call. If the realloc moves the buffer to a new address (which C runtime realloc does as an optimization when the allocation needs to grow), the saved pointer addresses invalid memory. When line 48 dereferences it, the write hits freed memory that may have been reallocated for another purpose, causing silent data corruption.

The fix replaces absolute pointer tracking with offset-based tracking. Line 32 now saves `record_offset = list->length`, a position within the buffer, rather than `list->data + list->length`, an absolute address. Offsets remain valid even when the buffer is relocated. After the realloc completes (which updates `list->data` to the new address), line 48 uses `list->data[record_offset + RECORD_SIZE - 1]` to compute the correct absolute address from the current buffer base and the saved offset. Line 49 then updates `list->last_write_ptr` to reflect the record's position in the possibly-relocated buffer, ensuring the field stays current.

This approach aligns with CWE-416/c guidance: "After `realloc()`, the old pointer is invalid whether or not the block moved—assign the result to a temporary and overwrite the original only once it is non-NULL." The fix avoids holding stale pointers altogether by using offsets that remain valid across reallocations.

## Behaviour changes

- **Line 32**: Changed from storing an absolute pointer (`list->data + list->length`) to storing a relative offset (`list->length`). This offset remains valid even if the realloc operation relocates the buffer.
- **Line 48**: Changed from dereferencing the stale pointer (`list->last_write_ptr[RECORD_SIZE - 1]`) to computing the address from the current buffer base and the saved offset (`list->data[record_offset + RECORD_SIZE - 1]`). This ensures the write always targets the correct location regardless of realloc behavior.
- **Line 49**: Added assignment `list->last_write_ptr = list->data + record_offset;` to synchronize the `last_write_ptr` field with the current buffer location after the record is written. Previously it was set before the potential realloc and left stale.
- **Result**: The status byte is now written to the correct memory location even when the buffer grows and is relocated. Repeated appends that trigger growth no longer corrupt the buffer.
