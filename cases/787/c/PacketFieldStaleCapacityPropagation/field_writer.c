#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    if (offset > destCapacity || valueLen > destCapacity - offset) {
        return;
    }

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    memcpy(dest + offset, value, valueLen);
}
