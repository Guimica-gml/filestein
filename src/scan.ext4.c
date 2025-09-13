#include "./ext4.h"

typedef struct {
    Fs_Thread id;
    Arena arena;
    File_Set file_set;
    size_t inode_size;
    size_t block_size;
    size_t block_groups_index;
    size_t block_groups_count;
    size_t inodes_per_group;
    Fs_Mount_Point *mount_point;
    struct ext4_group_desc *group_descs;
    Scan_Progress_Bar *progress_bar;
} Scan_Inode_Thread;

typedef struct {
    Fs_Thread id;
    Arena arena;
    size_t block_size;
    size_t chunk_offset;
    size_t blocks_count;
    Scan_Files files;
    Fs_Mount_Point *mount_point;
    File_Set *file_set;
    Scan_Progress_Bar *progress_bar;
} Scan_Chunk_Thread;

typedef struct {
    Fs_Thread id;
    Arena arena;
    Fs_Mount_Point mount_point;
    Scan_Progress_Report progress_report;
    Scan_Inode_Thread *scan_inode_threads;
    Scan_Chunk_Thread *scan_chunk_threads;
    size_t threads_count;
} Scan_Device_Thread;

void scan_extent(Arena *arena, Fs_Device *device, size_t extent_offset, size_t block_size, File_Set *file_set) {
    struct ext4_extent_header header;
    int64_t bytes_read = fs_read_device_off(device, &header, sizeof(header), extent_offset);
    assert(bytes_read == sizeof(header));

    if (header.eh_magic != 0xF30A || header.eh_entries <= 0) {
        return;
    }

    size_t extent_data_offset = extent_offset + sizeof(header);
    if (header.eh_depth == 0) {
        // We only care about the first extent because we only want the beginning of the file
        struct ext4_extent first_extent;
        int64_t bytes_read = fs_read_device_off(device, &first_extent, sizeof(first_extent), extent_data_offset);
        assert(bytes_read == sizeof(first_extent));

        size_t file_begin_index = (size_t) first_extent.ee_start_lo | ((size_t) first_extent.ee_start_hi << 32);
        size_t file_begin_offset = file_begin_index * block_size;

        file_set_add(arena, file_set, file_begin_offset);
    } else {
        struct ext4_extent_idx first_extent;
        int64_t bytes_read = fs_read_device_off(device, &first_extent, sizeof(first_extent), extent_data_offset);
        assert(bytes_read == sizeof(first_extent));

        size_t leaf_index = (size_t) first_extent.ei_leaf_lo | ((size_t) first_extent.ei_leaf_hi << 32);
        size_t leaf_offset = leaf_index * block_size;
        scan_extent(arena, device, leaf_offset, block_size, file_set);
    }
}

void scan_inode(Arena *arena, Fs_Device *device, size_t inode_offset, size_t block_size, File_Set *file_set) {
    struct ext4_inode inode;
    int64_t bytes_read = fs_read_device_off(device, &inode, sizeof(inode), inode_offset);
    assert(bytes_read == sizeof(inode));

    uint16_t file_type = inode.i_mode & 0xF000;
    if (file_type != S_IFREG || inode.i_links_count <= 0) {
        return;
    }

    // We are only dealing with inode with extents for now
    if ((inode.i_flags & EXT4_EXTENTS_FL) != 0) {
        size_t extent_offset = inode_offset + offsetof(struct ext4_inode, i_block);
        scan_extent(arena, device, extent_offset, block_size, file_set);
    }
}

Fs_Thread_Result start_scan_inode_thread(void *arg) {
    Scan_Inode_Thread *info = arg;

    Fs_Device device = FS_DEVICE_INVALID;
    bool device_opened = fs_open_device(&device, info->mount_point);
    assert(device_opened);

    for (size_t i = 0; i < info->block_groups_count; ++i) {
        struct ext4_group_desc *group_desc = &info->group_descs[info->block_groups_index + i];
        size_t inode_table_index =
            (size_t) group_desc->bg_inode_table_lo | ((size_t) group_desc->bg_inode_table_hi << 32);
        size_t inode_table_offset = inode_table_index * info->block_size;

        for (size_t j = 0; j < info->inodes_per_group; ++j) {
            size_t inode_offset = inode_table_offset + (info->inode_size * j);
            scan_inode(&info->arena, &device, inode_offset, info->block_size, &info->file_set);
        }

        atomic_fetch_add(&info->progress_bar->value, 1);
    }

    fs_close_device(&device);
    return FS_THREAD_RESULT_OK;
}

typedef bool(*Try_Parse_File_Func)(Arena *arena, Fs_Device *device, size_t file_offset, Scan_Files *files);

typedef struct {
    Nob_String_View magic;
    Try_Parse_File_Func try_parse_file;
} File_Header_Entry;

uint32_t read_uint32_be(Fs_Device *device) {
    uint8_t bytes[4];
    fs_read_device(device, &bytes[3], sizeof(uint8_t));
    fs_read_device(device, &bytes[2], sizeof(uint8_t));
    fs_read_device(device, &bytes[1], sizeof(uint8_t));
    fs_read_device(device, &bytes[0], sizeof(uint8_t));
    return *(uint32_t*)bytes;
}

// These values exist in case part of the file is valid, but the rest is corrupted
// If the parsing goes for too long it will be interrupted (these numbers are arbitrary)
#define PNG_PARSE_MAX_FILE_SIZE (4096 * 1024 * 10)
#define PNG_PARSE_MAX_CHUNK_SIZE (4096 * 10 * 2)

bool try_parse_png(Arena *arena, Fs_Device *device, size_t file_offset, Scan_Files *files) {
    Scan_File file = {0};
    file.type = SCAN_FILE_TYPE_PNG;

    const char *name_fmt = "0x%016lX";
    int name_size = snprintf(NULL, 0, name_fmt, file_offset);

    file.name = arena_alloc(arena, name_size + 1);
    snprintf(file.name, name_size, name_fmt, file_offset);
    file.name[name_size] = '\0';

    if (!fs_set_device_offset(device, file_offset)) {
        return false;
    }

    char *expected_magic = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
    uint8_t end_chunk[4] = { 'I', 'E', 'N', 'D' };

    unsigned char file_magic[8];
    int64_t bytes_read = fs_read_device(device, file_magic, sizeof(file_magic));
    if (bytes_read != sizeof(file_magic)) return false;
    if (memcmp(file_magic, expected_magic, sizeof(file_magic)) != 0) return false;
    arena_da_append_many(arena, &file.bytes, file_magic, sizeof(file_magic));

    while (true) {
        if (file.bytes.count >= PNG_PARSE_MAX_FILE_SIZE) {
            return false;
        }

        uint32_t length = read_uint32_be(device);
        if (length >= PNG_PARSE_MAX_CHUNK_SIZE) return false;

        uint8_t chunk_type[4];
        bytes_read = fs_read_device(device, chunk_type, sizeof(chunk_type));
        if ((uint32_t) bytes_read != sizeof(chunk_type)) return false;

        uint8_t *a = (uint8_t*) &length;
        arena_da_append_many(arena, &file.bytes, &a[3], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[2], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[1], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, &a[0], sizeof(uint8_t));
        arena_da_append_many(arena, &file.bytes, chunk_type, sizeof(chunk_type));

        arena_da_reserve(arena, &file.bytes, file.bytes.count + length);
        unsigned char *chunk_data = &file.bytes.items[file.bytes.count];

        int64_t bytes_read = fs_read_device(device, chunk_data, length);
        if ((uint32_t) bytes_read != length) {
            return false;
        }
        file.bytes.count += length;

        unsigned char crc[4];
        bytes_read = fs_read_device(device, crc, sizeof(crc));
        if ((uint32_t) bytes_read != sizeof(crc)) return false;
        arena_da_append_many(arena, &file.bytes, crc, sizeof(crc));

        if (memcmp(&chunk_type, end_chunk, sizeof(chunk_type)) == 0) {
            break;
        }
    }

    arena_da_append(arena, files, file);
    return true;
}

static_assert(SCAN_FILE_TYPE_COUNT == 2, "Amount of file types changed, please update code here!");
static File_Header_Entry file_header_entries[] = {
    [SCAN_FILE_TYPE_UNKNOWN] = { .magic = SV(""),                                 .try_parse_file = NULL },
    [SCAN_FILE_TYPE_PNG]     = { .magic = SV("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"), .try_parse_file = try_parse_png },
};

Fs_Thread_Result start_scan_chunk_thread(void *arg) {
    Scan_Chunk_Thread *info = arg;

    Fs_Device device = FS_DEVICE_INVALID;
    bool device_opened = fs_open_device(&device, info->mount_point);
    assert(device_opened);

    size_t max_magic_size = 0;
    for (size_t i = 0; i < NOB_ARRAY_LEN(file_header_entries); ++i) {
        max_magic_size = max(max_magic_size, file_header_entries[i].magic.count);
    }
    char *magic = arena_alloc(&info->arena, max_magic_size);

    for (size_t i = 0; i < info->blocks_count; ++i) {
        atomic_fetch_add(&info->progress_bar->value, 1);

        size_t block_offset = info->chunk_offset + (info->block_size * i);
        if (file_set_contains(info->file_set, block_offset)) {
            continue;
        }

        int64_t bytes_read = fs_read_device_off(&device, magic, max_magic_size, block_offset);
        if (bytes_read < 0) {
            continue;
        }

        for (size_t j = 1; j < SCAN_FILE_TYPE_COUNT; ++j) {
            File_Header_Entry header_entry = file_header_entries[j];
            if (bytes_read < (int64_t) header_entry.magic.count
                || memcmp(magic, header_entry.magic.data, header_entry.magic.count) != 0)
            {
                continue;
            }

            Arena_Mark mark = arena_snapshot(&info->arena);
            bool success = header_entry.try_parse_file(&info->arena, &device, block_offset, &info->files);
            if (success) break;
            arena_rewind(&info->arena, mark);
        }
    }

    return FS_THREAD_RESULT_OK;
}

Fs_Thread_Result start_scan_device_thread(void *arg) {
    Scan_Device_Thread *info = arg;

    Fs_Device device = FS_DEVICE_INVALID;
    if (!fs_open_device(&device, &info->mount_point)) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", info->mount_point.device_path, fs_get_last_error());
        goto cleanup;
    }

    struct ext4_super_block super_block;
    int64_t bytes_read = fs_read_device_off(&device, &super_block, sizeof(super_block), 0x400);
    assert(bytes_read == sizeof(super_block));

    if (super_block.s_magic != 0xEF53) {
        fprintf(stderr, "Error: mount point is not formatted as ext4\n");
        goto cleanup;
    }

    size_t inode_size;
    if (super_block.s_rev_level == EXT4_DYNAMIC_REV) {
        inode_size = super_block.s_inode_size;
    } else if (super_block.s_rev_level == EXT4_GOOD_OLD_REV) {
        inode_size = 256;
    } else {
        fprintf(stderr, "Error: ext4 revision set to weird value\n");
        goto cleanup;
    }

    size_t volume_size;
    if (!fs_get_volume_size(&device, &volume_size)) {
        fprintf(stderr, "Error: coould not get partition size: %s\n", fs_get_last_error());
        goto cleanup;
    }

    size_t block_size = 1024 << super_block.s_log_block_size;
    size_t block_group_size = super_block.s_blocks_per_group * block_size;
    size_t block_group_count = volume_size / block_group_size;

    size_t group_descs_size = block_group_count * sizeof(struct ext4_group_desc);
    struct ext4_group_desc *group_descs = arena_alloc(&info->arena, group_descs_size);
    bytes_read = fs_read_device_off(&device, group_descs, group_descs_size, 0x1000);
    assert(bytes_read == (int64_t) group_descs_size);

    size_t block_groups_per_cpu = block_group_count / info->threads_count;
    size_t rest = block_group_count % info->threads_count;
    info->progress_report.bars[0].max_value = block_group_count;

    for (size_t i = 0; i < info->threads_count; ++i) {
        info->scan_inode_threads[i] = (Scan_Inode_Thread) {
            .inode_size = inode_size,
            .block_size = block_size,
            .block_groups_index = block_groups_per_cpu * i,
            .block_groups_count = block_groups_per_cpu,
            .inodes_per_group = super_block.s_inodes_per_group,
            .group_descs = group_descs,
            .mount_point = &info->mount_point,
            .progress_bar = &info->progress_report.bars[0],
        };
        if (i >= info->threads_count - 1) {
            info->scan_inode_threads[i].block_groups_count += rest;
        }

        if (!fs_spawn_thread(&info->scan_inode_threads[i].id, start_scan_inode_thread, &info->scan_inode_threads[i])) {
            fprintf(stderr, "Error: could not create thread: %s\n", fs_get_last_error());
            goto cleanup;
        }
    }

    File_Set *file_set = arena_alloc(&info->arena, sizeof(File_Set));
    memset(file_set, 0, sizeof(File_Set));

    for (size_t i = 0; i < info->threads_count; ++i) {
        fs_wait_thread(&info->scan_inode_threads[i].id);
        for (size_t j = 0; j < FILE_SET_BUCKET_CAP; ++j) {
            File_Offs *offs = &info->scan_inode_threads[i].file_set.bucket[j];
            arena_da_append_many(&info->arena, &file_set->bucket[j], offs->items, offs->count);
        }
        arena_free(&info->scan_inode_threads[i].arena);
    }

    size_t total_block_count = volume_size / block_size;
    size_t blocks_per_chunk = total_block_count / info->threads_count;
    rest = total_block_count % info->threads_count;
    info->progress_report.bars[1].max_value = total_block_count;

    for (size_t i = 0; i < info->threads_count; ++i) {
        info->scan_chunk_threads[i] = (Scan_Chunk_Thread) {
            .block_size = block_size,
            .chunk_offset = i * blocks_per_chunk * block_size,
            .blocks_count = blocks_per_chunk,
            .file_set = file_set,
            .mount_point = &info->mount_point,
            .progress_bar = &info->progress_report.bars[1],
        };
        if (i >= info->threads_count - 1) {
            info->scan_chunk_threads[i].blocks_count += rest;
        }

        if (!fs_spawn_thread(&info->scan_chunk_threads[i].id, start_scan_chunk_thread, &info->scan_chunk_threads[i])) {
            fprintf(stderr, "Error: could not create thread: %s\n", fs_get_last_error());
            goto cleanup;
        }
    }

    for (size_t i = 0; i < info->threads_count; ++i) {
        fs_wait_thread(&info->scan_chunk_threads[i].id);
    }

cleanup:
    info->progress_report.done = true;
    if (fs_is_device_valid(&device)) fs_close_device(&device);
    return FS_THREAD_RESULT_OK;
}

Scan scan_ext4_mount_point(Arena *arena, Fs_Mount_Point *mount_point) {
    Scan scan = {0};
    scan.type = FS_MOUNT_POINT_EXT4;

    Scan_Device_Thread *scan_device = arena_alloc(arena, sizeof(Scan_Device_Thread));
    memset(scan_device, 0, sizeof(Scan_Device_Thread));

    size_t threads_count = fs_get_cpu_count();

    Scan_Inode_Thread *scan_inode_threads = arena_alloc(&scan_device->arena, sizeof(Scan_Inode_Thread) * threads_count);
    memset(scan_inode_threads, 0, sizeof(Scan_Inode_Thread) * threads_count);

    Scan_Chunk_Thread *scan_chunk_threads = arena_alloc(&scan_device->arena, sizeof(Scan_Chunk_Thread) * threads_count);
    memset(scan_chunk_threads, 0, sizeof(Scan_Chunk_Thread) * threads_count);

    scan_device->mount_point = *mount_point;
    scan_device->scan_inode_threads = scan_inode_threads;
    scan_device->scan_chunk_threads = scan_chunk_threads;
    scan_device->threads_count = threads_count;
    scan_device->progress_report.bars_count = 2;

    if (!fs_spawn_thread(&scan_device->id, start_scan_device_thread, scan_device)) {
        fprintf(stderr, "Error: could not create thread: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    scan.data = scan_device;
    return scan;
}

Scan_Progress_Report scan_ext4_get_progress_report(void *info) {
    Scan_Device_Thread *scan_device = info;
    return scan_device->progress_report;
}

void scan_ext4_collect_files(void *info, Arena *arena, Scan_Files *files) {
    Scan_Device_Thread *scan_device = info;
    for (size_t i = 0; i < scan_device->threads_count; ++i) {
        Scan_Files *orig_files = &scan_device->scan_chunk_threads[i].files;
        for (size_t j = 0; j < orig_files->count; ++j) {
            Scan_File *orig_file = &orig_files->items[j];
            Scan_File copy_file = {0};

            size_t name_len = strlen(orig_file->name);
            copy_file.name = arena_alloc(arena, name_len + 1);
            memcpy(copy_file.name, orig_file->name, name_len);
            copy_file.name[name_len] = '\0';

            arena_da_append_many(arena, &copy_file.bytes, orig_file->bytes.items, orig_file->bytes.count);
            copy_file.type = orig_file->type;
            arena_da_append(arena, files, copy_file);
        }
        arena_free(&scan_device->scan_chunk_threads[i].arena);
    }
}

void scan_ext4_free(void *info) {
    Scan_Device_Thread *scan_device = info;
    arena_free(&scan_device->arena);
}
