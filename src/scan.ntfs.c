#include "./ntfs.h"

typedef struct {
    uint8_t *items;
    size_t count;
    size_t capacity;
} Bytes;

typedef struct {
    Ntfs_Record *items;
    size_t count;
    size_t capacity;
} Ntfs_Records;

bool read_ntfs_attr(Arena *arena, Fs_Device *device, Ntfs_Attr *attr) {
    int64_t known_size = offsetof(Ntfs_Attr, resident);
    int64_t bytes_read = fs_read_device(device, attr, known_size);
    if (bytes_read != known_size) {
        return false;
    }

    int64_t bs_size = (attr->non_resident_flag)
        ? sizeof(attr->non_resident)
        : sizeof(attr->resident);
    bytes_read = fs_read_device(device, (uint8_t*)attr + known_size, bs_size);
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
        ? (attr->length - offsetof(Ntfs_Attr, name))
        : attr->resident.attr_length;
    attr->content = arena_alloc(arena, content_length);
    assert(attr->content != NULL);
    bytes_read = fs_read_device(device, attr->content, content_length);
    if (bytes_read != content_length) {
        return false;
    }

    // NOTE(nic): There's padding until the next divisble by 8 address
    //            0x30 -> File Name attribute
    if (attr->attr_type == 0x30) {
        size_t curr_offset;
        if (!fs_get_device_offset(device, &curr_offset)) {
            return false;
        }

        size_t remainder = curr_offset % 8;
        size_t final_offset = curr_offset + (8 - remainder);
        if (!fs_set_device_offset(device, final_offset)) {
            return false;
        }
    }

    return true;
}

bool find_ntfs_data(Arena *arena, Fs_Device *device, Ntfs_Attr *attr, size_t attrs_offset) {
    if (!fs_set_device_offset(device, attrs_offset)) {
        return false;
    }
    while (attr->attr_type != (uint32_t)0xFFFFFFFF) {
        if (!read_ntfs_attr(arena, device, attr)) {
            return false;
        }
        if (attr->attr_type == 0x80) {
            return true;
        }
    }
    assert(0 && "unreachable: no data attribute?");
}

bool get_bytes_from_data(Arena *arena, Fs_Device *device, Ntfs_Attr attr, size_t cluster_size, Bytes *bytes) {
    assert(attr.attr_type == 0x80 && "Not a Data attribute");
    assert(attr.non_resident_flag && "TODO: implement resident version of this code");

    size_t cursor = 0;
    size_t global_offset = 0;

    while (true) {
        uint8_t head = attr.content[cursor++];
        if (head == 0) {
            break;
        }

        uint8_t length_bytes_count = head & 0x0F;
        uint8_t offset_bytes_count = (head & 0xF0) >> 4;

        uint32_t length_in_clusters = 0;
        memcpy(&length_in_clusters, &attr.content[cursor], length_bytes_count);
        cursor += length_bytes_count;

        uint32_t offset_in_clusters = 0;
        memcpy(&offset_in_clusters, &attr.content[cursor], offset_bytes_count);
        cursor += offset_bytes_count;

        global_offset += offset_in_clusters * cluster_size;
        if (!fs_set_device_offset(device, global_offset)) {
            return false;
        }

        int64_t length = length_in_clusters * cluster_size;
        arena_da_reserve(arena, bytes, bytes->count + length);

        uint8_t *start = &bytes->items[bytes->count];
        int64_t bytes_read = fs_read_device(device, start, length);
        if (bytes_read != length) {
            return false;
        }
        bytes->count += length;
    }

    return true;
}

bool get_records_from_data(Arena *arena, Fs_Device *device, Ntfs_Attr attr, size_t cluster_size, Ntfs_Records *records) {
    assert(attr.attr_type == 0x80 && "Not a Data attribute");
    Bytes bytes = {0};

    if (!get_bytes_from_data(arena, device, attr, cluster_size, &bytes)) {
        return false;
    }

    size_t record_count = bytes.count / cluster_size;
    for (size_t i = 0; i < record_count; ++i) {
        Ntfs_Record record;
        memcpy(&record, bytes.items + i*cluster_size, sizeof(Ntfs_Record));
        arena_da_append(arena, records, record);
    }

    return true;
}

Scan scan_ntfs_mount_point(Arena *arena, Fs_Mount_Point *mount_point) {
    (void) arena;

    Fs_Device device;
    if (!fs_open_device(&device, mount_point)) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", mount_point->device_path, fs_get_last_error());
        return (Scan) {0};
    }

    Ntfs_Pbs pbs = {0};
    int64_t bytes_read = fs_read_device(&device, &pbs, sizeof(pbs));
    if (bytes_read != sizeof(pbs)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    size_t cluster_size = pbs.sectors_per_cluster * pbs.bytes_per_sector;
    size_t mft_offset = pbs.mft_cluster_number * cluster_size;

    if (!fs_set_device_offset(&device, mft_offset)) {
        fprintf(stderr, "Error: could not set file pointer: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    Ntfs_Record record;
    bytes_read = fs_read_device(&device, &record, sizeof(record));
    if (bytes_read != sizeof(record)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    size_t attrs_offset = mft_offset + record.attributes_offset;
    Ntfs_Attr attr = {0};
    if (!find_ntfs_data(arena, &device, &attr, attrs_offset)) {
        fprintf(stderr, "Error: could not find mft data attribute: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    Ntfs_Records records = {0};
    if (!get_records_from_data(arena, &device, attr, cluster_size, &records)) {
        fprintf(stderr, "Error: could not get file records from mft: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    __asm__("int3");
    fs_close_device(&device);
    return (Scan) {0};
}

Scan_Progress_Report scan_ntfs_get_progress_report(void *info) {
    (void) info;
    return (Scan_Progress_Report) {0};
}

void scan_ntfs_collect_files(void *info, Arena *arena, Scan_Files *files) {
    (void) info;
    (void) arena;
    (void) files;
}

void scan_ntfs_free(void *info) {
    (void) info;
}
