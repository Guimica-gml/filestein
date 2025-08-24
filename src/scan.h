#ifndef SCAN_H_
#define SCAN_H_

#include <stdlib.h>
#include <stdbool.h>

#include "./fs.h"
#include "./arena.h"

typedef enum {
    SCAN_FILE_TYPE_UNKNOWN,
    SCAN_FILE_TYPE_PNG,
    SCAN_FILE_TYPE_COUNT,
} Scan_File_Type;

typedef struct {
    unsigned char *items;
    size_t count;
    size_t capacity;
} Scan_File_Builder;

typedef struct {
    char *name;
    Scan_File_Builder bytes;
    Scan_File_Type type;
} Scan_File;

typedef struct {
    Scan_File *items;
    size_t count;
    size_t capacity;
} Scan_Files;

typedef struct {
    size_t value;
    size_t max_value;
} Scan_Progress_Bar;

#define SCAN_PROGRESS_BAR_CAP 8
typedef struct {
    bool done;
    size_t bars_count;
    Scan_Progress_Bar bars[SCAN_PROGRESS_BAR_CAP];
} Scan_Progress_Report;

typedef struct {
    Fs_Mount_Point_Type type;
    void *data;
} Scan;

Scan scan_mount_point(Arena *arena, Fs_Mount_Point *mount_point);
Scan_Progress_Report scan_get_progress_report(Scan scan);
void scan_collect_files(Scan scan, Arena *arena, Scan_Files *files);
void scan_free(Scan scan);

const char *scan_file_type_get_ext(Scan_File_Type type);
const char *scan_file_type_to_cstr(Scan_File_Type type);

void scan_hexdump(void *items, size_t items_count, size_t offset);

#endif // SCAN_H_
