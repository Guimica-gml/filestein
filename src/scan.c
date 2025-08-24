#include "./scan.h"
#include "./nob.h"

#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

typedef struct {
    size_t *items;
    size_t count;
    size_t capacity;
} File_Offs;

#define FILE_SET_BUCKET_CAP 4096
typedef struct {
    File_Offs bucket[FILE_SET_BUCKET_CAP];
} File_Set;

size_t hash_bytes(void *buf, size_t buf_size) {
    size_t hash = 17;
    for (size_t i = 0; i < buf_size; ++i) {
        hash = (hash * 13) + ((uint8_t*)buf)[i];
    }
    return hash;
}

void file_set_add(Arena *arena, File_Set *set, size_t file_offset) {
    size_t index = hash_bytes(&file_offset, sizeof(file_offset)) % FILE_SET_BUCKET_CAP;
    File_Offs *file_offs = &set->bucket[index];
    // Usually we would need to check if the value is already there
    // but in our case we know it's not necessary
    arena_da_append(arena, file_offs, file_offset);
}

bool file_set_contains(File_Set *set, size_t file_offset) {
    size_t index = hash_bytes(&file_offset, sizeof(file_offset)) % FILE_SET_BUCKET_CAP;
    File_Offs *file_offs = &set->bucket[index];
    for (size_t i = 0; i < file_offs->count; ++i) {
        if (file_offs->items[i] == file_offset) {
            return true;
        }
    }
    return false;
}

#include "./scan.ntfs.c"
#include "./scan.ext4.c"

Scan scan_mount_point(Arena *arena, Fs_Mount_Point *mount_point) {
    switch (mount_point->type) {
    case FS_MOUNT_POINT_EXT4: return scan_ext4_mount_point(arena, mount_point);
    case FS_MOUNT_POINT_NTFS: return scan_ntfs_mount_point(arena, mount_point);
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

Scan_Progress_Report scan_get_progress_report(Scan scan) {
    switch (scan.type) {
    case FS_MOUNT_POINT_EXT4: return scan_ext4_get_progress_report(scan.data);
    case FS_MOUNT_POINT_NTFS: return scan_ntfs_get_progress_report(scan.data);
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

void scan_collect_files(Scan scan, Arena *arena, Scan_Files *files) {
    switch (scan.type) {
    case FS_MOUNT_POINT_EXT4: scan_ext4_collect_files(scan.data, arena, files); break;
    case FS_MOUNT_POINT_NTFS: scan_ntfs_collect_files(scan.data, arena, files); break;
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

void scan_free(Scan scan) {
    if (scan.data == NULL) {
        return;
    }
    switch (scan.type) {
    case FS_MOUNT_POINT_EXT4: scan_ext4_free(scan.data); break;
    case FS_MOUNT_POINT_NTFS: scan_ntfs_free(scan.data); break;
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

const char *scan_file_type_get_ext(Scan_File_Type type) {
    switch (type) {
    case SCAN_FILE_TYPE_UNKNOWN: return "bin";
    case SCAN_FILE_TYPE_PNG: return "png";
    default:
        assert(0 && "unreachable");
        exit(1); // dead code, so cl.exe shuts up
    }
}

const char *scan_file_type_to_cstr(Scan_File_Type type) {
    switch (type) {
    case SCAN_FILE_TYPE_UNKNOWN: return "UNKNOWN";
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
