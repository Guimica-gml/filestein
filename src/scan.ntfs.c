#include "./ntfs.h"

Scan scan_ntfs_mount_point(Arena *arena, Fs_Mount_Point *mount_point) {
    (void) arena;

    Fs_Device device;
    if (!fs_open_device(&device, mount_point)) {
        fprintf(stderr, "Error: could not open file `%s`: %s\n", mount_point->device_path, fs_get_last_error());
        return (Scan) {0};
    }

    struct ntfs_pbs pbs = {0};

    int64_t bytes_read = fs_read_device(&device, &pbs, sizeof(pbs));
    if (bytes_read != sizeof(pbs)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        return (Scan) {0};
    }
    scan_hexdump(&pbs, sizeof(pbs), 0);

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

    struct ntfs_record record;
    bytes_read = fs_read_device(&device, &record, sizeof(record));
    if (bytes_read != sizeof(record)) {
        fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
        return (Scan) {0};
    }
    scan_hexdump(&record, sizeof(record), mft_offset);

    printf("-------------\n");
    printf("attributes_offset: %u\n", record.attributes_offset);
    printf("-------------\n");

    size_t attrs_offset = mft_offset + record.attributes_offset;
    if (!fs_set_device_offset(&device, attrs_offset)) {
        fprintf(stderr, "Error: could not set file pointer: %s\n", fs_get_last_error());
        return (Scan) {0};
    }

    uint32_t attr_type = 0;
    do {
        bytes_read = fs_read_device(&device, &attr_type, sizeof(attr_type));
        if (bytes_read != sizeof(attr_type)) {
            fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
            return (Scan) {0};
        }
        scan_hexdump(&attr_type, sizeof(attr_type), attrs_offset);

        printf("-------------\n");
        printf("attr_type: 0x%04X\n", attr_type);

        if (attr_type == 0x10) {
            struct ntfs_attr_standard_info attr;
            bytes_read = fs_read_device(&device, &attr, sizeof(attr));
            if (bytes_read != sizeof(attr)) {
                fprintf(stderr, "Error: could not read device: %s\n", fs_get_last_error());
                return (Scan) {0};
            }
            printf("-------------\n");
            scan_hexdump(&attr, sizeof(attr), 0);
        } else {
            assert(0 && "unimplemented");
        }
    } while (attr_type != 0xFFFFFFFF);

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
