#include <stdio.h>
#include <string.h>

int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    strcpy(message, username);
    strcat(message, ":");
    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    strcat(message, action);

    int written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
