#ifndef FS_H_
#define FS_H_

#include <stdlib.h>
#include <stdbool.h>

#include "./arena.h"

#define FS_PATH_CAP 256

enum fs_file_type {
    FS_FILE_TYPE_UNKNOWN,
    FS_FILE_TYPE_PNG,
    FS_FILE_TYPE_COUNT,
};

struct fs_mount_point {
    char path[FS_PATH_CAP];
    char device_path[FS_PATH_CAP];
};

struct fs_mount_points {
    struct fs_mount_point *items;
    size_t count;
    size_t capacity;
};

struct fs_file_builder {
    unsigned char *items;
    size_t count;
    size_t capacity;
};

struct fs_file {
    char *name; // may be null
    struct fs_file_builder bytes;
    enum fs_file_type type;
};

struct fs_files {
    struct fs_file *items;
    size_t count;
    size_t capacity;
};

struct fs_progress_bar {
    size_t value;
    size_t max_value;
};

#define FS_PROGRESS_BAR_CAP 8
struct fs_progress_report {
    bool done;
    size_t bars_count;
    struct fs_progress_bar bars[FS_PROGRESS_BAR_CAP];
};

bool fs_get_mount_points(Arena *arena, struct fs_mount_points *mount_points);
void *fs_scan_mount_point(Arena *arena, struct fs_mount_point *mount_point, struct fs_files *files);
struct fs_progress_report fs_scan_get_progress_report(void *id);

// Common interface
const char *fs_file_type_get_ext(enum fs_file_type type);
const char *fs_file_type_to_cstr(enum fs_file_type type);
void fs_hexdump(void *items_, size_t items_count, size_t offset);

#endif // FS_H_
