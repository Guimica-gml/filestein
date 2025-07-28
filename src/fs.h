#ifndef FS_H_
#define FS_H_

#include <stdlib.h>
#include <stdbool.h>

#include "./arena.h"

#define FS_PATH_CAP 256

typedef enum {
    FS_FILE_TYPE_UNKNOWN,
    FS_FILE_TYPE_PNG,
    FS_FILE_TYPE_COUNT,
} Fs_File_Type;

typedef struct {
    char path[FS_PATH_CAP];
    char device_path[FS_PATH_CAP];
} Fs_Mount_Point;

typedef struct {
    Fs_Mount_Point *items;
    size_t count;
    size_t capacity;
} Fs_Mount_Points;

typedef struct {
    unsigned char *items;
    size_t count;
    size_t capacity;
} Fs_File_Builder;

typedef struct {
    char *name;
    Fs_File_Builder bytes;
    Fs_File_Type type;
} Fs_File;

typedef struct {
    Fs_File *items;
    size_t count;
    size_t capacity;
} Fs_Files;

typedef struct {
    size_t value;
    size_t max_value;
} Fs_Progress_Bar;

#define FS_PROGRESS_BAR_CAP 8
typedef struct {
    bool done;
    size_t bars_count;
    Fs_Progress_Bar bars[FS_PROGRESS_BAR_CAP];
} Fs_Progress_Report;

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points);
void *fs_scan_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Fs_Files *files);
Fs_Progress_Report fs_scan_get_progress_report(void *id);

// Common interface
const char *fs_file_type_get_ext(Fs_File_Type type);
const char *fs_file_type_to_cstr(Fs_File_Type type);
void fs_hexdump(void *items_, size_t items_count, size_t offset);

#endif // FS_H_
