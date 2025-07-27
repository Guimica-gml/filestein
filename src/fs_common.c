#include "./fs.h"

#include <stdio.h>
#include <ctype.h>
#include <assert.h>

const char *fs_file_type_get_ext(enum fs_file_type type) {
    switch (type) {
    case FS_FILE_TYPE_UNKNOWN: return "bin";
    case FS_FILE_TYPE_PNG: return "png";
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

const char *fs_file_type_to_cstr(enum fs_file_type type) {
    switch (type) {
    case FS_FILE_TYPE_UNKNOWN: return "UNKNOWN";
    case FS_FILE_TYPE_PNG: return "PNG";
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

void fs_hexdump(void *items_, size_t items_count, size_t offset) {
    const unsigned char *items = items_;
    size_t max_row_size = 16;
    for (size_t i = 0; i < items_count; i += max_row_size) {
        fprintf(stderr, "%016zX | ", i + offset);
        size_t row_size = (items_count - i >= max_row_size) ? max_row_size : items_count - i;
        size_t actual_size = 0;
        for (size_t j = 0; j < row_size; ++j) {
            actual_size += fprintf(stderr, "%02X ", items[i + j]);
            if (((j + 1) % (max_row_size / 2)) == 0 && j < row_size - 1) {
                actual_size += fprintf(stderr, " ");
            }
        }
        size_t expected_size = 3 * max_row_size + 1;
        for (size_t j = 0; j < (expected_size - actual_size); ++j) {
            fprintf(stderr, " ");
        }
        fprintf(stderr, "| ");
        for (size_t j = 0; j < row_size; ++j) {
            fprintf(stderr, "%c", isprint(items[i + j]) ? items[i + j] : '.');
        }
        fprintf(stderr, "\n");
    }
}
