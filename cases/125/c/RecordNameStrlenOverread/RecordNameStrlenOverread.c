#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct Record {
    uint8_t name[16];
    uint32_t flags;
};

size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);
}
