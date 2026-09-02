#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_PACKET_CAPACITY 256

void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen);

int encode_packet(size_t requestedCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    uint8_t *packet = malloc(requestedCapacity);
    if (packet == NULL) {
        return -1;
    }

    write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
    free(packet);
    return 0;
}
