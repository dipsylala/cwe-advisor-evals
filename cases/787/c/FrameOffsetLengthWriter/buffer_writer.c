#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
