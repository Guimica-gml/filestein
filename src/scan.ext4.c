#include "./ext4.h"

typedef struct {
    Arena *arena;

    Fs_Mutex inode_scan_mutex;
    Fs_Mutex chunk_scan_mutex;
    Fs_Mutex progress_report_mutex;

    Scan_Progress_Report progress_report;
    Fs_Mount_Point *mount_point;
    Scan_Files *files;
} Scan_Device_Thread_Info;

typedef struct {
    Arena *arena;
    Fs_Device *device;

    size_t inode_size;
    size_t block_size;
    size_t block_groups_index;
    size_t block_groups_count;
    size_t inodes_per_group;

    Fs_Mutex *inode_scan_mutex;
    Fs_Mutex *progress_report_mutex;

    Scan_Progress_Bar *progress_bar;
    struct ext4_group_desc *group_descs;
    File_Set *file_set;
} Scan_Inode_Thread_Info;

typedef struct {
    Arena *arena;
    Fs_Device *device;

    size_t block_size;
    size_t chunk_offset;
    size_t blocks_count;

    Fs_Mutex *chunk_scan_mutex;
    Fs_Mutex *progress_report_mutex;

    File_Set *file_set;
    Scan_Progress_Bar *progress_bar;
    Scan_Files *files;
} Scan_Chunk_Thread_Info;

void scan_extent(Arena *arena, Fs_Device *device, size_t extent_offset, size_t block_size, File_Set *file_set, Fs_Mutex *mutex) {
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

        fs_lock_mutex(mutex);
        file_set_add(arena, file_set, file_begin_offset);
        fs_unlock_mutex(mutex);
    } else {
        struct ext4_extent_idx first_extent;
        int64_t bytes_read = fs_read_device_off(device, &first_extent, sizeof(first_extent), extent_data_offset);
        assert(bytes_read == sizeof(first_extent));

        size_t leaf_index = (size_t) first_extent.ei_leaf_lo | ((size_t) first_extent.ei_leaf_hi << 32);
        size_t leaf_offset = leaf_index * block_size;
        scan_extent(arena, device, leaf_offset, block_size, file_set, mutex);
    }
}

void scan_inode(Arena *arena, Fs_Device *device, size_t inode_offset, size_t block_size, File_Set *file_set, Fs_Mutex *mutex) {
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
        scan_extent(arena, device, extent_offset, block_size, file_set, mutex);
    }
}

void *start_scan_inode_thread(void *arg) {
    Scan_Inode_Thread_Info *info = arg;

    for (size_t i = 0; i < info->block_groups_count; ++i) {
        struct ext4_group_desc group_desc = info->group_descs[info->block_groups_index + i];
        size_t inode_table_index = group_desc.bg_inode_table_lo | ((size_t) group_desc.bg_inode_table_hi << 32);
        size_t inode_table_offset = inode_table_index * info->block_size;

        for (size_t j = 0; j < info->inodes_per_group; ++j) {
            size_t inode_offset = inode_table_offset + (info->inode_size * j);
            scan_inode(info->arena, info->device, inode_offset, info->block_size, info->file_set, info->inode_scan_mutex);
        }

        fs_lock_mutex(info->progress_report_mutex);
        info->progress_bar->value += 1;
        fs_unlock_mutex(info->progress_report_mutex);
    }

    return NULL;
}

void *start_scan_chunk_thread(void *arg) {
    (void) arg;
    return NULL;
}

void *start_scan_device_thread(void *arg) {
    Scan_Device_Thread_Info *info = arg;

    int result = 0;
    Arena scratch = {0};

    Fs_Device device;
    if (!fs_open_device(&device, info->mount_point)) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", info->mount_point->device_path, strerror(errno));
        nob_return_defer(1);
    }

    struct ext4_super_block super_block;
    int64_t bytes_read = fs_read_device_off(&device, &super_block, sizeof(super_block), 0x400);
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
    if (!fs_get_volume_size(&device, &partition_size)) {
        fprintf(stderr, "Error: coould not get partition size: %s\n", strerror(errno));
        nob_return_defer(1);
    }

    size_t block_size = 1024 << super_block.s_log_block_size;
    size_t block_group_size = super_block.s_blocks_per_group * block_size;
    size_t block_group_count = partition_size / block_group_size;

    size_t group_descs_size = block_group_count * sizeof(struct ext4_group_desc);
    struct ext4_group_desc *group_descs = arena_alloc(&scratch, group_descs_size);
    bytes_read = fs_read_device_off(&device, group_descs, group_descs_size, 0x1000);
    assert(bytes_read == (int64_t) group_descs_size);

    File_Set *file_set = arena_alloc(&scratch, sizeof(File_Set));
    memset(file_set, 0, sizeof(File_Set));

    size_t cpu_count = fs_get_cpu_count();
    {
        size_t block_groups_per_cpu = block_group_count / cpu_count;
        size_t rest = block_group_count % cpu_count;

        fs_lock_mutex(&info->progress_report_mutex);
        info->progress_report.bars[0].max_value = block_group_count;
        fs_unlock_mutex(&info->progress_report_mutex);

        Scan_Inode_Thread_Info *thread_infos = arena_alloc(&scratch, sizeof(Scan_Inode_Thread_Info) * cpu_count);
        memset(thread_infos, 0, sizeof(Scan_Inode_Thread_Info) * cpu_count);

        Fs_Thread *threads = arena_alloc(&scratch, sizeof(Fs_Thread) * cpu_count);
        memset(threads, 0, sizeof(Fs_Thread) * cpu_count);

        for (size_t i = 0; i < cpu_count; ++i) {
            thread_infos[i] = (Scan_Inode_Thread_Info) {
                .arena = &scratch,
                .device = &device,
                .inode_size = inode_size,
                .block_size = block_size,
                .block_groups_index = block_groups_per_cpu * i,
                .block_groups_count = block_groups_per_cpu,
                .inode_scan_mutex = &info->inode_scan_mutex,
                .progress_report_mutex = &info->progress_report_mutex,
                .progress_bar = &info->progress_report.bars[0],
                .inodes_per_group = super_block.s_inodes_per_group,
                .group_descs = group_descs,
                .file_set = file_set,
            };
            if (i >= cpu_count - 1) {
                thread_infos[i].block_groups_count += rest;
            }

            if (!fs_spawn_thread(&threads[i], start_scan_inode_thread, &thread_infos[i])) {
                fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
                nob_return_defer(1);
            }
        }

        for (size_t i = 0; i < cpu_count; ++i) {
            fs_wait_thread(&threads[i]);
        }
    }

    {
        size_t total_block_count = partition_size / block_size;
        size_t blocks_per_chunk = total_block_count / cpu_count;
        size_t rest = total_block_count % cpu_count;

        fs_lock_mutex(&info->progress_report_mutex);
        info->progress_report.bars[1].max_value = total_block_count;
        fs_unlock_mutex(&info->progress_report_mutex);

        Scan_Chunk_Thread_Info *thread_infos = arena_alloc(&scratch, sizeof(Scan_Chunk_Thread_Info) * cpu_count);
        memset(thread_infos, 0, sizeof(Scan_Chunk_Thread_Info) * cpu_count);

        Fs_Thread *threads = arena_alloc(&scratch, sizeof(Fs_Thread) * cpu_count);
        memset(threads, 0, sizeof(Fs_Thread) * cpu_count);

        for (size_t i = 0; i < cpu_count; ++i) {
            thread_infos[i] = (Scan_Chunk_Thread_Info) {
                .arena = info->arena,
                .device = &device,
                .block_size = block_size,
                .chunk_offset = i * blocks_per_chunk,
                .blocks_count = blocks_per_chunk,
                .file_set = file_set,
                .chunk_scan_mutex = &info->chunk_scan_mutex,
                .progress_report_mutex = &info->progress_report_mutex,
                .progress_bar = &info->progress_report.bars[1],
                .files = info->files,
            };
            if (i >= (size_t) (cpu_count - 1)) {
                thread_infos[i].blocks_count += rest;
            }

            if (!fs_spawn_thread(&threads[i], start_scan_chunk_thread, &thread_infos[i])) {
                fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
                nob_return_defer(1);
            }
        }

        for (size_t i = 0; i < cpu_count; ++i) {
            fs_wait_thread(&threads[i]);
        }
    }

defer:
    fs_lock_mutex(&info->progress_report_mutex);
    info->progress_report.done = true;
    fs_unlock_mutex(&info->progress_report_mutex);

    arena_free(&scratch);
    if (fs_is_device_valid(&device)) fs_close_device(&device);
    return (void*)(uintptr_t)result;
}

Scan scan_ext4_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Scan_Files *files) {
    Scan scan = {0};
    scan.type = FS_MOUNT_POINT_EXT4;

    Scan_Device_Thread_Info *info = arena_alloc(arena, sizeof(Scan_Device_Thread_Info));
    memset(info, 0, sizeof(Scan_Device_Thread_Info));

    info->arena = arena;
    info->mount_point = mount_point;
    info->files = files;
    info->progress_report.bars_count = 2;

    fs_create_mutex(&info->inode_scan_mutex);
    fs_create_mutex(&info->chunk_scan_mutex);
    fs_create_mutex(&info->progress_report_mutex);

    Fs_Thread thread;
    if (!fs_spawn_thread(&thread, start_scan_device_thread, info)) {
        fprintf(stderr, "Error: could not create thread: %s\n", strerror(errno));
        return (Scan) {0};
    }

    scan.data = info;
    return scan;
}

Scan_Progress_Report scan_ext4_get_progress_report(void *info) {
    Scan_Device_Thread_Info *casted_info = info;
    fs_lock_mutex(&casted_info->progress_report_mutex);
    Scan_Progress_Report report = casted_info->progress_report;
    fs_unlock_mutex(&casted_info->progress_report_mutex);
    return report;
}
