#include "./ntfs.h"

Scan scan_ntfs_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Scan_Files *files) {
    (void) arena;
    //(void) mount_point;
    (void) files;

    Fs_Device device;
    bool success = fs_open_device(&device, mount_point);
    if (!success) {
        printf("Error: %s\n", fs_get_last_error());
        fflush(stdout);
        return (Scan) {0};
    }

    size_t volume_size;
    success = fs_get_volume_size(&device, &volume_size);
    assert(success);
    printf("Volume size: %zu\n", volume_size);
    fflush(stdout);

    {
        size_t off = 0;
        unsigned char buf[1024];
        int64_t bytes_read = fs_read_device_off(&device, buf, sizeof(buf), off);
        if (bytes_read != sizeof(buf)) {
            printf("Error: %s\n", fs_get_last_error());
            fflush(stdout);
            return (Scan) {0};
        }
        scan_hexdump(buf, sizeof(buf), off);
    }

    printf("---------------\n");

    {
        size_t off = 2;
        unsigned char buf[512];
        int64_t bytes_read = fs_read_device_off(&device, buf, sizeof(buf), off);
        if (bytes_read != sizeof(buf)) {
            printf("Error: %s\n", fs_get_last_error());
            fflush(stdout);
            return (Scan) {0};
        }
        scan_hexdump(buf, sizeof(buf), off);
    }

    fs_close_device(&device);
    return (Scan) {0};
}

Scan_Progress_Report scan_ntfs_get_progress_report(void *info) {
    (void) info;
    return (Scan_Progress_Report) {0};
}

void scan_ntfs_free(void *info) {
    (void) info;
}
