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
