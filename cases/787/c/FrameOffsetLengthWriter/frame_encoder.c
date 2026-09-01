#include <stddef.h>
#include <stdint.h>

struct Frame {
    uint8_t bytes[256];
    size_t capacity;
};

void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length);

void encode_frame(struct Frame *frame, size_t offset, const uint8_t *payload, size_t length) {
    write_payload(frame->bytes, frame->capacity, offset, payload, length);
}
