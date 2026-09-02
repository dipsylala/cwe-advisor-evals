#include <stdio.h>
#include <string.h>

int read_command_line(char *out, size_t out_capacity)
{
    char line[64];

    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    gets(line);

    size_t len = strlen(line);
    if (len >= out_capacity) {
        return -1;
    }
    strcpy(out, line);
    return 0;
}
