## Verdict
CONFIRMED

## Source
```c
#include <string.h>

static void append_display_name(char *destination, const char *first, const char *last) {
    strcpy(destination, first);
    strcat(destination, " ");
    strcat(destination, last);
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    append_display_name(display_name, first, last);
    strcpy(out, display_name);
}
```

## Fix
```c
#include <string.h>

static void append_display_name(char *destination, size_t dest_size, const char *first, const char *last) {
    if (dest_size == 0) return;
    
    strncpy(destination, first, dest_size - 1);
    destination[dest_size - 1] = '\0';
    
    size_t current_len = strlen(destination);
    if (current_len < dest_size - 1) {
        strncat(destination, " ", dest_size - current_len - 1);
    }
    
    current_len = strlen(destination);
    if (current_len < dest_size - 1) {
        strncat(destination, last, dest_size - current_len - 1);
    }
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    append_display_name(display_name, sizeof(display_name), first, last);
    strcpy(out, display_name);
}
```

## Explanation
The vulnerability is a classic stack-based buffer overflow caused by unbounded string functions. The `append_display_name` function receives a fixed 32-byte stack buffer but uses `strcpy` (line 4) and `strcat` (lines 5-6) without any bounds checking. If the `first` or `last` parameters exceed the buffer capacity—either individually or cumulatively with the space separator—the write will overflow the stack buffer and corrupt memory.

The fix introduces three key changes:

1. **Buffer size parameter**: `append_display_name` now accepts `dest_size` so it knows the buffer's actual capacity.

2. **Bounded string operations**: Replace unbounded `strcpy` with `strncpy(..., dest_size - 1)` and always null-terminate explicitly. Replace unbounded `strcat` with `strncat`, recalculating remaining space after each operation.

3. **Length checks**: Before each concatenation, verify that remaining buffer space exists. This prevents attempts to write past the buffer end.

The caller passes `sizeof(display_name)` to convey the 32-byte limit, ensuring that any combination of `first`, the space, and `last` will be truncated rather than overflow the stack.
