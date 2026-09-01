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
