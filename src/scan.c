#include "./scan.h"
#include "./nob.h"

#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "./scan.ntfs.c"
#include "./scan.ext4.c"

typedef struct {
    Scan (*start)(Arena *arena, Fs_Mount_Point *mount_point);
    Scan_Progress_Report (*get_progress_report)(void *info);
    void (*collect_files)(void *info, Arena *arena, Scan_Files *files);
    void (*deinit)(void *info);
} Scan_Interface;

static_assert(FS_MOUNT_POINT_COUNT == 2, "Non-exhaustive enumerator check, please update code below");
Scan_Interface scan_interfaces[] = {
    [FS_MOUNT_POINT_EXT4] = {
        .start = scan_ext4_mount_point,
        .get_progress_report = scan_ext4_get_progress_report,
        .collect_files = scan_ext4_collect_files,
        .deinit = scan_ext4_free,
    },
    [FS_MOUNT_POINT_NTFS] = {
        .start = scan_ntfs_mount_point,
        .get_progress_report = scan_ntfs_get_progress_report,
        .collect_files = scan_ntfs_collect_files,
        .deinit = scan_ntfs_free,
    },
};

Scan scan_start(Arena *arena, Fs_Mount_Point *mount_point) {
    Scan_Interface *interface = &scan_interfaces[mount_point->type];
    return interface->start(arena, mount_point);
}

Scan_Progress_Report scan_get_progress_report(Scan scan) {
    Scan_Interface *interface = &scan_interfaces[scan.type];
    return interface->get_progress_report(scan.data);
}

void scan_collect_files(Scan scan, Arena *arena, Scan_Files *files) {
    Scan_Interface *interface = &scan_interfaces[scan.type];
    interface->collect_files(scan.data, arena, files);
}

void scan_deinit(Scan scan) {
    if (scan.data == NULL) {
        return;
    }
    Scan_Interface *interface = &scan_interfaces[scan.type];
    interface->deinit(scan.data);
}

const char *scan_file_type_get_ext(Scan_File_Type type) {
    static_assert(SCAN_FILE_TYPE_COUNT == 3, "Amount of file types changed, please update code here!");
    switch (type) {
    case SCAN_FILE_TYPE_UNKNOWN: return "bin";
    case SCAN_FILE_TYPE_PDF: return "pdf";
    case SCAN_FILE_TYPE_PNG: return "png";
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

const char *scan_file_type_to_cstr(Scan_File_Type type) {
    static_assert(SCAN_FILE_TYPE_COUNT == 3, "Amount of file types changed, please update code here!");
    switch (type) {
    case SCAN_FILE_TYPE_UNKNOWN: return "UNKNOWN";
    case SCAN_FILE_TYPE_PDF: return "PDF";
    case SCAN_FILE_TYPE_PNG: return "PNG";
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

void scan_hexdump(void *items, size_t items_count, size_t offset) {
    uint8_t *bytes = items;
    size_t max_row_size = 16;
    for (size_t i = 0; i < items_count; i += max_row_size) {
        printf("%016zX | ", i + offset);
        size_t row_size = (items_count - i >= max_row_size) ? max_row_size : items_count - i;
        size_t actual_size = 0;
        for (size_t j = 0; j < row_size; ++j) {
            actual_size += printf("%02X ", bytes[i + j]);
            if (((j + 1) % (max_row_size / 2)) == 0 && j < row_size - 1) {
                actual_size += printf(" ");
            }
        }
        size_t expected_size = 3 * max_row_size + 1;
        for (size_t j = 0; j < (expected_size - actual_size); ++j) {
            printf(" ");
        }
        printf("| ");
        for (size_t j = 0; j < row_size; ++j) {
            printf("%c", isprint(bytes[i + j]) ? bytes[i + j] : '.');
        }
        printf("\n");
    }
}
