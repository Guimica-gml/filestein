#include "./ntfs.h"

typedef struct {
    size_t *items;
    size_t count;
    size_t capacity;
} Offsets;

typedef struct {
    Fs_Thread id;
    Arena arena;
    Fs_Mount_Point mount_point;
    Scan_Progress_Report progress_report;
    Scan_Files files;
} Scan_Ntfs_Device_Thread;

bool read_ntfs_attr(Arena *arena, Fs_Device device, Ntfs_Attr *attr) {
    int64_t attr_type_size = sizeof(attr->attr_type);
    int64_t bytes_read = fs_read_device(device, &attr->attr_type, attr_type_size);
    if (bytes_read != attr_type_size) {
        return false;
    }

    if (attr->attr_type == 0xFFFFFFFF || attr->attr_type == 0x00) {
        return true;
    }

    int64_t known_size = offsetof(Ntfs_Attr, resident) - attr_type_size;
    bytes_read = fs_read_device(device, (uint8_t*)attr + attr_type_size, known_size);
    if (bytes_read != known_size) {
        return false;
    }

    int64_t bs_size = (attr->non_resident_flag)
        ? sizeof(attr->non_resident)
        : sizeof(attr->resident);
    bytes_read = fs_read_device(device, (uint8_t*)attr + known_size + attr_type_size, bs_size);
    if (bytes_read != bs_size) {
        return false;
    }

    if (attr->name_length > 0) {
        int64_t name_length = attr->name_length * 2;
        attr->name = arena_alloc(arena, name_length);
        assert(attr->name != NULL);
        bytes_read = fs_read_device(device, attr->name, name_length);
        if (bytes_read != name_length) {
            return false;
        }
    }

    int64_t content_length = (attr->non_resident_flag)
        ? (attr->length - (attr->name_length * 2) - offsetof(Ntfs_Attr, name))
        : attr->resident.attr_length;
    attr->content = arena_alloc(arena, content_length);
    assert(attr->content != NULL);
    bytes_read = fs_read_device(device, attr->content, content_length);
    if (bytes_read != content_length) {
        return false;
    }

    // NOTE(nic): There's padding until the next divisble by 8 address
    size_t curr_offset;
    if (!fs_get_device_offset(device, &curr_offset)) {
        return false;
    }

    size_t remainder = curr_offset % 8;
    size_t final_offset = curr_offset + (8 - remainder);
    if (remainder != 0 && !fs_set_device_offset(device, final_offset)) {
        return false;
    }

    return true;
}

bool find_ntfs_data(Arena *arena, Fs_Device device, Ntfs_Attr *attr, size_t attrs_offset) {
    if (!fs_set_device_offset(device, attrs_offset)) {
        return false;
    }

    Arena_Mark mark = arena_snapshot(arena);
    while (true) {
        if (!read_ntfs_attr(arena, device, attr)) {
            return false;
        }
        if (attr->attr_type == 0x80) {
            return true;
        } else if (attr->attr_type == (uint32_t)0xFFFFFFFF) {
            break;
        }
        arena_rewind(arena, mark);
    }
    assert(0 && "unreachable: no data attribute?");
}

static inline uint32_t read_bytes_to_uint32(uint8_t* buffer, size_t n) {
    assert(n <= 4);
    uint32_t result = 0;
    for (size_t i = 0; i < n; ++i) {
        result |= (uint32_t)buffer[i] << (i * 8);
    }
    return result;
}

bool get_bytes_from_data(
    Arena *arena,
    Fs_Device device,
    Ntfs_Attr attr,
    size_t cluster_size,
    Scan_File_Type *type, // optional
    Offsets *offs,        // optional
    Scan_File_Builder *file_builder)
{
    assert(attr.attr_type == 0x80 && "Not a Data attribute");

    if (!attr.non_resident_flag) {
        arena_da_append_many(arena, file_builder, attr.content, attr.resident.attr_length);
        return true;
    }

    size_t cursor = 0;
    size_t global_offset = 0;

    if (type != NULL) {
        *type = SCAN_FILE_TYPE_UNKNOWN;
    }

    bool first_run = true;
    while (true) {
        uint8_t head = attr.content[cursor++];
        if (head == 0) {
            break;
        }

        uint8_t length_bytes_count = (head & 0x0F);
        uint8_t offset_bytes_count = (head & 0xF0) >> 4;

        uint32_t length_in_clusters = read_bytes_to_uint32(attr.content + cursor, length_bytes_count);
        cursor += length_bytes_count;

        uint32_t offset_in_clusters = read_bytes_to_uint32(attr.content + cursor, offset_bytes_count);
        cursor += offset_bytes_count;

        global_offset += offset_in_clusters * cluster_size;
        if (!fs_set_device_offset(device, global_offset)) {
            return false;
        }

        if (offs != NULL) {
            for (size_t i = 0; i < length_in_clusters; ++i) {
                size_t off = global_offset + i*cluster_size;
                arena_da_append(arena, offs, off);
            }
        }

        int64_t length = length_in_clusters * cluster_size;
        arena_da_reserve(arena, file_builder, file_builder->count + length);

        uint8_t *start = &file_builder->items[file_builder->count];
        int64_t bytes_read = fs_read_device(device, start, length);
        if (bytes_read != length) {
            return false;
        }
        file_builder->count += length;

        if (type != NULL && first_run) {
            // TODO(nic): add other types of files later (like pdf)
            char *magic = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
            int64_t magic_size = 8;
            if (bytes_read < magic_size || memcmp(start, magic, magic_size) != 0) {
                return true;
            }
            *type = SCAN_FILE_TYPE_PNG;
        }
        first_run = false;
    }

    return true;
}

bool get_attr_offs_from_data(Arena *arena, Fs_Device device, Ntfs_Attr attr, size_t cluster_size, Offsets *offs) {
    assert(attr.attr_type == 0x80 && "Not a Data attribute");
    Arena temp_arena = {0};
    Scan_File_Builder file_builder = {0};

    Offsets record_offs = {0};
    if (!get_bytes_from_data(&temp_arena, device, attr, cluster_size, NULL, &record_offs, &file_builder)) {
        return false;
    }

    char type[4] = { 'F', 'I', 'L', 'E' };
    size_t type_size = 4;

    for (size_t i = 0; i < record_offs.count; ++i) {
        Ntfs_Record *record = (Ntfs_Record *)(file_builder.items + i*cluster_size);
        size_t attr_off = record_offs.items[i] + record->attributes_offset;
        if (memcmp(record->record_type, type, type_size) == 0 && record->hard_link_count == 0) {
            arena_da_append(arena, offs, attr_off);
        }
    }

    arena_free(&temp_arena);
    return true;
}

char *get_filename_from_attr(Arena *arena, Ntfs_Attr attr) {
    assert(attr.attr_type == 0x30 && "Not a File Name attribute");
    assert(!attr.non_resident_flag && "File Name attribute should always be resident");

    char *stupid_name = (char *)(attr.content + 66);
    size_t name_length = (attr.resident.attr_length - 66) / 2;

    char *name = arena_alloc(arena, name_length + 1);
    for (size_t i = 0; i < name_length; ++i) {
        name[i] = stupid_name[i * 2];
    }
    name[name_length] = '\0';

    return name;
}

bool get_files_from_attr_offs(Arena *arena, Fs_Device device, Offsets *offs, size_t cluster_size, Scan_Progress_Bar *progress_bar, Scan_Files *files) {
    Ntfs_Attr attr = {0};

    for (size_t i = 0; i < offs->count; ++i) {
        Scan_File file = {0};
        size_t off = offs->items[i];
        if (!fs_set_device_offset(device, off)) {
            return false;
        }

        while (true) {
            if (!read_ntfs_attr(arena, device, &attr)) {
                return false;
            }

            if (attr.attr_type == 0x30) {
                file.name = get_filename_from_attr(arena, attr);
            } else if (attr.attr_type == 0x80) {
                if (!get_bytes_from_data(arena, device, attr, cluster_size, &file.type, NULL, &file.bytes)) {
                    return false;
                }
            } else if (attr.attr_type == (uint32_t)0x00 || attr.attr_type == (uint32_t)0xFFFFFFFF) {
                if (file.name != NULL && file.type != SCAN_FILE_TYPE_UNKNOWN && file.bytes.count > 0) {
                    arena_da_append(arena, files, file);
                }
                break;
            }
        }

        atomic_fetch_add(&progress_bar->value, 1);
    }

    return true;
}

Fs_Thread_Result start_ntfs_scan_device_thread(void *arg) {
    Scan_Ntfs_Device_Thread *info = arg;

    Fs_Device device = FS_DEVICE_INVALID;
    if (!fs_open_device(&device, &info->mount_point)) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", info->mount_point.device_path, fs_get_last_error());
        goto cleanup;
    }

    Ntfs_Pbs pbs = {0};
    int64_t bytes_read = fs_read_device(device, &pbs, sizeof(pbs));
    if (bytes_read != sizeof(pbs)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        goto cleanup;
    }

    size_t cluster_size = pbs.sectors_per_cluster * pbs.bytes_per_sector;
    size_t mft_offset = pbs.mft_cluster_number * cluster_size;

    if (!fs_set_device_offset(device, mft_offset)) {
        fprintf(stderr, "Error: could not set file pointer: %s\n", fs_get_last_error());
        goto cleanup;
    }

    Ntfs_Record mft_record;
    bytes_read = fs_read_device(device, &mft_record, sizeof(mft_record));
    if (bytes_read != sizeof(mft_record)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        goto cleanup;
    }

    size_t attrs_offset = mft_offset + mft_record.attributes_offset;
    Ntfs_Attr data_attr = {0};
    if (!find_ntfs_data(&info->arena, device, &data_attr, attrs_offset)) {
        fprintf(stderr, "Error: could not find mft data attribute: %s\n", fs_get_last_error());
        goto cleanup;
    }

    Offsets offsets = {0};
    if (!get_attr_offs_from_data(&info->arena, device, data_attr, cluster_size, &offsets)) {
        fprintf(stderr, "Error: could not get file records from mft: %s\n", fs_get_last_error());
        goto cleanup;
    }
    info->progress_report.bars[0].max_value = offsets.count;

    if (!get_files_from_attr_offs(&info->arena, device, &offsets, cluster_size, &info->progress_report.bars[0], &info->files)) {
        fprintf(stderr, "Error: could not get file data from file records: %s\n", fs_get_last_error());
        goto cleanup;
    }

cleanup:
    info->progress_report.done = true;
    if (fs_is_device_valid(device)) fs_close_device(device);
    return FS_THREAD_RESULT_OK;
}

Scan scan_ntfs_mount_point(Arena *arena, Fs_Mount_Point *mount_point) {
    Scan scan = {0};
    scan.type = FS_MOUNT_POINT_NTFS;

    Scan_Ntfs_Device_Thread *scan_device = arena_alloc(arena, sizeof(Scan_Ntfs_Device_Thread));
    memset(scan_device, 0, sizeof(Scan_Ntfs_Device_Thread));

    scan_device->mount_point = *mount_point;
    scan_device->progress_report.bars_count = 1;

    if (!fs_spawn_thread(&scan_device->id, start_ntfs_scan_device_thread, scan_device)) {
        fprintf(stderr, "Error: could not create thread: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    scan.data = scan_device;
    return scan;
}

Scan_Progress_Report scan_ntfs_get_progress_report(void *info) {
    Scan_Ntfs_Device_Thread *scan_device = info;
    return scan_device->progress_report;
}

void scan_ntfs_collect_files(void *info, Arena *arena, Scan_Files *files) {
    Scan_Ntfs_Device_Thread *scan_device = info;
    for (size_t i = 0; i < scan_device->files.count; ++i) {
        Scan_File *orig_file = &scan_device->files.items[i];
        Scan_File copy_file = {0};

        size_t name_len = strlen(orig_file->name);
        copy_file.name = arena_alloc(arena, name_len + 1);
        memcpy(copy_file.name, orig_file->name, name_len);
        copy_file.name[name_len] = '\0';

        arena_da_append_many(arena, &copy_file.bytes, orig_file->bytes.items, orig_file->bytes.count);
        copy_file.type = orig_file->type;
        arena_da_append(arena, files, copy_file);
    }
}

void scan_ntfs_free(void *info) {
    Scan_Ntfs_Device_Thread *scan_device = info;
    arena_free(&scan_device->arena);
}
