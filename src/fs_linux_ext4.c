#define _POSIX_C_SOURCE 200809L
#define _LARGEFILE64_SOURCE

#include "./fs.h"
#include "./ext4.h"
#include "./nob.h"
#include "./arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <pthread.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points) {
    bool result = true;
    const char *mounts_filepath = "/proc/mounts";

    FILE *file = fopen(mounts_filepath, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: could not open `%s`: %s\n", mounts_filepath, strerror(errno));
        nob_return_defer(false);
    }

#define BUFFER_CAP 2048
    char buffer[BUFFER_CAP] = {0};
    while (fgets(buffer, BUFFER_CAP, file) != NULL) {
        Nob_String_View sv = { strlen(buffer), buffer };

        Nob_String_View device_path = nob_sv_chop_by_delim(&sv, ' ');
        if (device_path.count <= 0 || *device_path.data != '/') {
            continue;
        }

        Nob_String_View path = nob_sv_chop_by_delim(&sv, ' ');
        Nob_String_View type = nob_sv_chop_by_delim(&sv, ' ');
        if (!nob_sv_eq(type, nob_sv_from_cstr("ext4"))) {
            continue;
        }

        Fs_Mount_Point mount_point = {0};
        memcpy(mount_point.path, path.data, min(path.count, FS_PATH_CAP));
        memcpy(mount_point.device_path, device_path.data, min(device_path.count, FS_PATH_CAP));

        arena_da_append(arena, mount_points, mount_point);
    }
#undef BUFFER_CAP

defer:
    if (file) fclose(file);
    return result;
}

typedef struct {
    off_t *items;
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

void file_set_add(Arena *arena, File_Set *set, off_t file_offset) {
    size_t index = hash_bytes(&file_offset, sizeof(file_offset)) % FILE_SET_BUCKET_CAP;
    File_Offs *file_offs = &set->bucket[index];
    // Usually we would need to check if the value is already there
    // but in our case we know it's not necessary
    arena_da_append(arena, file_offs, file_offset);
}

bool file_set_contains(File_Set *set, off_t file_offset) {
    size_t index = hash_bytes(&file_offset, sizeof(file_offset)) % FILE_SET_BUCKET_CAP;
    File_Offs *file_offs = &set->bucket[index];
    for (size_t i = 0; i < file_offs->count; ++i) {
        if (file_offs->items[i] == file_offset) {
            return true;
        }
    }
    return false;
}

static pthread_mutex_t inode_scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t chunk_scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t progress_report_mutex = PTHREAD_MUTEX_INITIALIZER;

void scan_extent(Arena *arena, int device, off_t extent_offset, size_t block_size, File_Set *file_set) {
    struct ext4_extent_header header;
    ssize_t bytes_read = pread(device, &header, sizeof(header), extent_offset);
    assert(bytes_read == sizeof(header));

    if (header.eh_magic != 0xF30A || header.eh_entries <= 0) {
        return;
    }

    off_t extent_data_offset = extent_offset + sizeof(header);
    if (header.eh_depth == 0) {
        // We only care about the first extent because we only want the beginning of the file
        struct ext4_extent first_extent;
        ssize_t bytes_read = pread(device, &first_extent, sizeof(first_extent), extent_data_offset);
        assert(bytes_read == sizeof(first_extent));

        size_t file_begin_index = first_extent.ee_start_lo | ((size_t) first_extent.ee_start_hi << 16);
        off_t file_begin_offset = file_begin_index * block_size;

        pthread_mutex_lock(&inode_scan_mutex);
        file_set_add(arena, file_set, file_begin_offset);
        pthread_mutex_unlock(&inode_scan_mutex);
    } else {
        struct ext4_extent_idx first_extent;
        ssize_t bytes_read = pread(device, &first_extent, sizeof(first_extent), extent_data_offset);
        assert(bytes_read == sizeof(first_extent));

        size_t leaf_index = first_extent.ei_leaf_lo | ((size_t) first_extent.ei_leaf_hi << 16);
        off_t leaf_offset = leaf_index * block_size;
        scan_extent(arena, device, leaf_offset, block_size, file_set);
    }
}

void scan_inode(Arena *arena, int device, off_t inode_offset, size_t block_size, File_Set *file_set) {
    struct ext4_inode inode;
    size_t bytes_read = pread(device, &inode, sizeof(inode), inode_offset);
    assert(bytes_read == sizeof(inode));

    uint16_t file_type = inode.i_mode & 0xF000;
    if (file_type != S_IFREG || inode.i_links_count <= 0) {
        return;
    }

    // We are only dealing with inode with extents for now
    if ((inode.i_flags & EXT4_EXTENTS_FL) != 0) {
        off_t extent_offset = inode_offset + offsetof(struct ext4_inode, i_block);
        scan_extent(arena, device, extent_offset, block_size, file_set);
    }
}

typedef struct {
    pthread_t *items;
    size_t count;
    size_t capacity;
} Threads;

typedef struct {
    Arena *arena;
    int device;

    size_t inode_size;
    size_t block_size;
    size_t block_groups_index;
    size_t block_groups_count;
    size_t inodes_per_group;

    Fs_Progress_Bar *progress_bar;
    struct ext4_group_desc *group_descs;
    File_Set *file_set;
} Scan_Inode_Thread_Info;

typedef struct {
    Arena *arena;
    int device;

    size_t block_size;
    size_t chunk_offset;
    size_t blocks_count;

    Fs_Progress_Bar *progress_bar;
    File_Set *file_set;
    Fs_Files *files;
} Scan_Chunk_Thread_Info;

typedef struct {
    Arena *arena;
    Fs_Progress_Report progress_report;
    Fs_Mount_Point *mount_point;
    Fs_Files *files;
} Scan_Device_Thread_Info;

void *start_scan_inode_thread(void *arg) {
    Scan_Inode_Thread_Info *info = arg;

    for (size_t i = 0; i < info->block_groups_count; ++i) {
        struct ext4_group_desc group_desc = info->group_descs[info->block_groups_index + i];
        size_t inode_table_index = group_desc.bg_inode_table_lo | ((size_t) group_desc.bg_inode_table_hi << 32);
        off_t inode_table_offset = inode_table_index * info->block_size;

        for (size_t j = 0; j < info->inodes_per_group; ++j) {
            off_t inode_offset = inode_table_offset + (info->inode_size * j);
            scan_inode(info->arena, info->device, inode_offset, info->block_size, info->file_set);
        }

        pthread_mutex_lock(&progress_report_mutex);
        info->progress_bar->value += 1;
        pthread_mutex_unlock(&progress_report_mutex);
    }

    return NULL;
}

typedef bool(*Try_Parse_File_Func)(Arena *arena, int device, off_t file_offset, Fs_Files *files);

typedef struct {
    Nob_String_View magic;
    Try_Parse_File_Func try_parse_file;
} File_Header_Entry;

uint32_t read_uint32_be(int device) {
    uint8_t bytes[4];
    read(device, &bytes[3], sizeof(uint8_t));
    read(device, &bytes[2], sizeof(uint8_t));
    read(device, &bytes[1], sizeof(uint8_t));
    read(device, &bytes[0], sizeof(uint8_t));
    return *(uint32_t*)bytes;
}

// These values exist in case part of the file is valid, but the rest is corrupted
// If the parsing goes for too long it will be interrupted (these numbers are arbitrary)
#define PNG_PARSE_MAX_FILE_SIZE (4096 * 1024 * 10)
#define PNG_PARSE_MAX_CHUNK_SIZE (4096 * 10)

bool try_parse_png(Arena *arena, int device, off_t file_offset, Fs_Files *files) {
    Fs_File file = {0};
    file.type = FS_FILE_TYPE_PNG;

    const char *name_fmt = "0x%016lX";
    int name_size = snprintf(NULL, 0, name_fmt, file_offset);

    pthread_mutex_lock(&chunk_scan_mutex);
    file.name = arena_alloc(arena, name_size + 1);
    pthread_mutex_unlock(&chunk_scan_mutex);

    snprintf(file.name, name_size, name_fmt, file_offset);
    file.name[name_size] = '\0';

    if (lseek64(device, file_offset, SEEK_SET) < 0) {
        return false;
    }

    char *expected_magic = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
    uint8_t end_chunk[4] = { 'I', 'E', 'N', 'D' };

    unsigned char file_magic[8];
    ssize_t bytes_read = read(device, file_magic, sizeof(file_magic));
    if (bytes_read != sizeof(file_magic)) return false;
    if (memcmp(file_magic, expected_magic, sizeof(file_magic)) != 0) return false;
    pthread_mutex_lock(&chunk_scan_mutex);
    arena_da_append_many(arena, &file.bytes, file_magic, sizeof(file_magic));
    pthread_mutex_unlock(&chunk_scan_mutex);

    while (true) {
        // TODO(nic): we should deallocate the memory used if parsing fails
        // Maybe not deallocate, but Arena has functions that allow us to reuse the memory
        if (file.bytes.count >= PNG_PARSE_MAX_FILE_SIZE) {
            return false;
        }

        uint32_t length = read_uint32_be(device);
        uint8_t chunk_type[4];
        bytes_read = read(device, chunk_type, sizeof(chunk_type));
        if ((uint32_t) bytes_read != sizeof(chunk_type)) return false;
        if (length >= PNG_PARSE_MAX_CHUNK_SIZE) return false;

        pthread_mutex_lock(&chunk_scan_mutex);
        uint8_t *a = (uint8_t*) &length;
        arena_da_append_many(arena, &file.bytes, &a[3], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[2], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[1], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[0], sizeof(uint8_t));

        arena_da_append_many(arena, &file.bytes, chunk_type, sizeof(chunk_type));
        pthread_mutex_unlock(&chunk_scan_mutex);

        unsigned char chunk_data[length];
        ssize_t bytes_read = read(device, chunk_data, length);
        if ((uint32_t) bytes_read != length) return false;
        pthread_mutex_lock(&chunk_scan_mutex);
        arena_da_append_many(arena, &file.bytes, chunk_data, sizeof(chunk_data));
        pthread_mutex_unlock(&chunk_scan_mutex);

        unsigned char crc[4];
        bytes_read = read(device, crc, sizeof(crc));
        if ((uint32_t) bytes_read != sizeof(crc)) return false;
        pthread_mutex_lock(&chunk_scan_mutex);
        arena_da_append_many(arena, &file.bytes, crc, sizeof(crc));
        pthread_mutex_unlock(&chunk_scan_mutex);

        if (memcmp(&chunk_type, end_chunk, sizeof(chunk_type)) == 0) {
            break;
        }
    }

    pthread_mutex_lock(&chunk_scan_mutex);
    arena_da_append(arena, files, file);
    pthread_mutex_unlock(&chunk_scan_mutex);
    return true;
}

static_assert(FS_FILE_TYPE_COUNT == 2, "Amount of file types changed, please update code here!");
static File_Header_Entry file_header_entries[] = {
    [FS_FILE_TYPE_UNKNOWN] = { .magic = SV(""),                                 .try_parse_file = NULL },
    [FS_FILE_TYPE_PNG]     = { .magic = SV("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"), .try_parse_file = try_parse_png },
};

void *start_scan_chunk_thread(void *arg) {
    Scan_Chunk_Thread_Info *info = (void*)arg;

    size_t max_magic_size = 0;
    for (size_t i = 0; i < NOB_ARRAY_LEN(file_header_entries); ++i) {
        max_magic_size = max(max_magic_size, file_header_entries[i].magic.count);
    }

    for (size_t i = 0; i < info->blocks_count; ++i) {
        pthread_mutex_lock(&progress_report_mutex);
        info->progress_bar->value += 1;
        pthread_mutex_unlock(&progress_report_mutex);

        off_t block_offset = info->chunk_offset + (info->block_size * i);
        if (file_set_contains(info->file_set, block_offset)) {
            continue;
        }

        char magic[max_magic_size];
        ssize_t bytes_read = pread(info->device, magic, max_magic_size, block_offset);
        if (bytes_read < 0) {
            fprintf(stderr, "Error: could not read %zu block: %s\n", block_offset / info->block_size, strerror(errno));
            continue;
        }

        for (size_t j = 1; j < FS_FILE_TYPE_COUNT; ++j) {
            File_Header_Entry header_entry = file_header_entries[j];
            if (bytes_read < (ssize_t) header_entry.magic.count || memcmp(magic, header_entry.magic.data, header_entry.magic.count) != 0) {
                continue;
            }

            bool success = header_entry.try_parse_file(info->arena, info->device, block_offset, info->files);
            if (success) break;
        }
    }
    return NULL;
}

void *start_scan_device_thread(void *arg) {
    Scan_Device_Thread_Info *info = (void*)arg;

    int result = 0;
    Arena scratch = {0};
    Arena file_set_arena = {0};

    int device = open(info->mount_point->device_path, O_RDONLY | O_LARGEFILE);
    if (device < 0) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", info->mount_point->device_path, strerror(errno));
        nob_return_defer(1);
    }

    struct ext4_super_block super_block;
    ssize_t bytes_read = pread(device, &super_block, sizeof(super_block), 0x400);
    assert(bytes_read == sizeof(super_block));

    if (super_block.s_magic != 0xEF53) {
        fprintf(stderr, "Error: mount point is not formatted as ext4\n");
        nob_return_defer(1);
    }

    size_t inode_size;
    if (super_block.s_rev_level == EXT4_DYNAMIC_REV) {
        inode_size = super_block.s_inode_size;
    } else if (super_block.s_rev_level == EXT4_GOOD_OLD_REV) {
        inode_size = 256;
    } else {
        fprintf(stderr, "Error: ext4 revision set to weird value\n");
        nob_return_defer(1);
    }

    size_t partition_size;
    if (ioctl(device, BLKGETSIZE64, &partition_size) < 0) {
        fprintf(stderr, "Error: coould not get partition size: %s\n", strerror(errno));
        nob_return_defer(1);
    }

    size_t block_size = 1024 << super_block.s_log_block_size;
    size_t block_group_size = super_block.s_blocks_per_group * block_size;
    size_t block_group_count = partition_size / block_group_size;

    size_t group_descs_size = block_group_count * sizeof(struct ext4_group_desc);
    struct ext4_group_desc *group_descs = arena_alloc(&scratch, group_descs_size);
    bytes_read = pread(device, group_descs, group_descs_size, 0x1000);
    assert(bytes_read == (ssize_t) group_descs_size);

    // Very big struct
    File_Set *file_set = arena_alloc(&file_set_arena, sizeof(File_Set));
    memset(file_set, 0, sizeof(File_Set));

    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_count = max(1, cpu_count);

    Threads threads = {0};
    {
        size_t block_groups_per_cpu = block_group_count / cpu_count;
        size_t rest = block_group_count % cpu_count;

        pthread_mutex_lock(&progress_report_mutex);
        info->progress_report.bars[0].max_value = block_group_count;
        pthread_mutex_unlock(&progress_report_mutex);

        Scan_Inode_Thread_Info *thread_infos = arena_alloc(&scratch, sizeof(Scan_Inode_Thread_Info) * cpu_count);
        memset(thread_infos, 0, sizeof(Scan_Inode_Thread_Info) * cpu_count);

        for (size_t i = 0; i < (size_t) cpu_count; ++i) {
            thread_infos[i] = (Scan_Inode_Thread_Info) {
                .arena = &file_set_arena,
                .device = device,
                .inode_size = inode_size,
                .block_size = block_size,
                .block_groups_index = block_groups_per_cpu * i,
                .block_groups_count = block_groups_per_cpu,
                .progress_bar = &info->progress_report.bars[0],
                .inodes_per_group = super_block.s_inodes_per_group,
                .group_descs = group_descs,
                .file_set = file_set,
            };
            if (i >= (size_t) (cpu_count - 1)) {
                thread_infos[i].block_groups_count += rest;
            }

            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, start_scan_inode_thread, &thread_infos[i])) {
                fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
                nob_return_defer(1);
            }
            arena_da_append(&scratch, &threads, thread_id);
        }

        for (size_t i = 0; i < threads.count; ++i) {
            pthread_join(threads.items[i], NULL);
        }
    }

    threads.count = 0;
    {
        size_t total_block_count = partition_size / block_size;
        size_t blocks_per_chunk = total_block_count / cpu_count;
        size_t rest = total_block_count % cpu_count;

        pthread_mutex_lock(&progress_report_mutex);
        info->progress_report.bars[1].max_value = total_block_count;
        pthread_mutex_unlock(&progress_report_mutex);

        Scan_Chunk_Thread_Info *thread_infos = arena_alloc(&scratch, sizeof(Scan_Chunk_Thread_Info) * cpu_count);
        memset(thread_infos, 0, sizeof(Scan_Chunk_Thread_Info) * cpu_count);

        for (size_t i = 0; i < (size_t) cpu_count; ++i) {
            thread_infos[i] = (Scan_Chunk_Thread_Info) {
                .arena = info->arena,
                .device = device,
                .block_size = block_size,
                .chunk_offset = i * blocks_per_chunk,
                .blocks_count = blocks_per_chunk,
                .file_set = file_set,
                .progress_bar = &info->progress_report.bars[1],
                .files = info->files,
            };
            if (i >= (size_t) (cpu_count - 1)) {
                thread_infos[i].blocks_count += rest;
            }

            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, start_scan_chunk_thread, &thread_infos[i])) {
                fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
                nob_return_defer(1);
            }
            arena_da_append(&scratch, &threads, thread_id);
        }

        for (size_t i = 0; i < threads.count; ++i) {
            pthread_join(threads.items[i], NULL);
        }
    }

defer:
    pthread_mutex_lock(&progress_report_mutex);
    info->progress_report.done = true;
    pthread_mutex_unlock(&progress_report_mutex);

    arena_free(&scratch);
    arena_free(&file_set_arena);
    if (device >= 0) close(device);
    return (void*)(uintptr_t)result;
}

void *fs_scan_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Fs_Files *files) {
    Scan_Device_Thread_Info *thread_info = arena_alloc(arena, sizeof(Scan_Device_Thread_Info));
    memset(thread_info, 0, sizeof(Scan_Device_Thread_Info));

    thread_info->arena = arena;
    thread_info->mount_point = mount_point;
    thread_info->files = files;
    thread_info->progress_report.bars_count = 2;

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, start_scan_device_thread, (void**)thread_info)) {
        fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
        return NULL;
    }

    return thread_info;
}

Fs_Progress_Report fs_scan_get_progress_report(void *id) {
    pthread_mutex_lock(&progress_report_mutex);
    Fs_Progress_Report report = ((Scan_Device_Thread_Info *)id)->progress_report;
    pthread_mutex_unlock(&progress_report_mutex);
    return report;
}
