#include "./ntfs.h"

typedef struct {
    Ntfs_Attr *items;
    size_t count;
    size_t capacity;
} Ntfs_Attrs;

typedef bool (*Ntfs_Read_Attr_Proc)(Arena *arena, Fs_Device *device, Ntfs_Attr *attr);

bool read_ntfs_standard_info(Arena *arena, Fs_Device *device, Ntfs_Attr *attr) {
    (void) arena;
    assert(!attr->header.non_resident_flag && "unreachable");
    attr->type = NTFS_ATTR_STANDARD_INFO;
    int64_t bytes_read = fs_read_device(device, &attr->as.std_info, sizeof(Ntfs_Standard_Info));
    if (bytes_read != sizeof(Ntfs_Standard_Info)) {
        return false;
    }
    return true;
}

bool read_ntfs_file_name(Arena *arena, Fs_Device *device, Ntfs_Attr *attr) {
    attr->type = NTFS_ATTR_FILE_NAME;
    assert(!attr->header.non_resident_flag && "unreachable");
    int64_t size = offsetof(Ntfs_File_Name, filename);
    int64_t bytes_read = fs_read_device(device, &attr->as.file_name, size);
    if (bytes_read != size) {
        return false;
    }

    int64_t actual_filename_length = attr->as.file_name.filename_length * 2;
    attr->as.file_name.filename = arena_alloc(arena, actual_filename_length);
    assert(attr->as.file_name.filename != NULL);
    bytes_read = fs_read_device(device, attr->as.file_name.filename, actual_filename_length);
    if (bytes_read != actual_filename_length) {
        return false;
    }

    // NOTE(nic): there's padding until the next addres divisble by 8
    size_t curr_offset;
    if (!fs_get_device_offset(device, &curr_offset)) {
        return false;
    }

    size_t remainder = curr_offset % 8;
    if (remainder != 0) {
        size_t final_offset = curr_offset + (8 - remainder);
        if (!fs_set_device_offset(device, final_offset)) {
            return false;
        }
    }

    return true;
}

bool read_ntfs_data(Arena *arena, Fs_Device *device, Ntfs_Attr *attr) {
    (void) arena;
    (void) device;

    assert(attr->header.non_resident_flag && "unreachable");
    attr->type = NTFS_ATTR_DATA;

    /*
    char *data_runs = arena_alloc(arena, size);
    assert(data_runs != NULL);

    int64_t bytes_read = fs_read_device(device, data_runs, size);
    if (bytes_read != size) {
        return false;
    }

    scan_hexdump(data_runs, size, 0x00);
    */
    return true;
}

typedef struct {
    uint32_t code;
    Ntfs_Read_Attr_Proc proc;
} Ntfs_Attr_Proc;

Ntfs_Attr_Proc ntfs_attr_procs[] = {
    { .code = 0x10, .proc = read_ntfs_standard_info },
    { .code = 0x30, .proc = read_ntfs_file_name },
    { .code = 0x80, .proc = read_ntfs_data },
    //{ .code = 0xB0, .proc = read_ntfs_bitmap },
};
size_t ntfs_attr_procs_count = sizeof(ntfs_attr_procs)/sizeof(*ntfs_attr_procs);

bool read_ntfs_attr_header(Arena *arena, Fs_Device *device, Ntfs_Attr_Header *header) {
    int64_t known_size = offsetof(Ntfs_Attr_Header, resident);
    int64_t bytes_read = fs_read_device(device, header, known_size);
    if (bytes_read != known_size) {
        return false;
    }

    int64_t bs_size = (header->non_resident_flag)
        ? sizeof(header->non_resident)
        : sizeof(header->resident);
    bytes_read = fs_read_device(device, (uint8_t*)header + known_size, bs_size);
    if (bytes_read != bs_size) {
        return false;
    }

    if (header->name_length > 0) {
        int64_t actual_length = header->name_length * 2;
        header->name = arena_alloc(arena, actual_length);
        assert(header->name != NULL);
        bytes_read = fs_read_device(device, header->name, actual_length);
        if (bytes_read != actual_length) {
            return false;
        }
    }

    if (header->non_resident_flag) {
        int64_t data_runs_length = header->length - offsetof(Ntfs_Attr_Header, data_runs);
        header->data_runs = arena_alloc(arena, data_runs_length);
        assert(header->data_runs != NULL);
        bytes_read = fs_read_device(device, header->data_runs, data_runs_length);
        if (bytes_read != data_runs_length) {
            return false;
        }
    }

    return true;
}

bool read_ntfs_attrs(Arena *arena, Ntfs_Attrs *attrs, Fs_Device *device, size_t attrs_offset) {
    if (!fs_set_device_offset(device, attrs_offset)) {
        return false;
    }

    while (true) {
        Ntfs_Attr_Header header = {0};
        if (!read_ntfs_attr_header(arena, device, &header)) {
            return false;
        }
        if (header.attr_type == (uint32_t)0xFFFFFFFF) {
            break;
        }

        bool found = false;
        for (size_t i = 0; i < ntfs_attr_procs_count; ++i) {
            Ntfs_Attr_Proc *proc = &ntfs_attr_procs[i];
            if (header.attr_type == proc->code) {
                Ntfs_Attr attr = {0};
                attr.header = header;
                if (!proc->proc(arena, device, &attr)) {
                    return false;
                }
                arena_da_append(arena, attrs, attr);
                found = true;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Error: unimplemented attribute type 0x%08X\n", header.attr_type);
            return false;
        }
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

    printf("-------------\n");
    printf("magic: 0x%08zX\n", pbs.magic);
    printf("bytes per sector: %d\n", pbs.bytes_per_sector);
    printf("sectors per cluster: %d\n", pbs.sectors_per_cluster);
    printf("mft cluster number: %ld\n", pbs.mft_cluster_number);
    printf("-------------\n");

    size_t mft_offset = pbs.mft_cluster_number * pbs.sectors_per_cluster * pbs.bytes_per_sector;
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
    Ntfs_Attrs attrs = {0};
    if (!read_ntfs_attrs(arena, &attrs, &device, attrs_offset)) {
        fprintf(stderr, "Error: could not read mft attributes: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

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
