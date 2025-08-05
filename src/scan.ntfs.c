#include "./ntfs.h"

Scan scan_ntfs_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Scan_Files *files) {
    (void) arena;
    (void) mount_point;
    (void) files;
    return (Scan) {0};
}

Scan_Progress_Report scan_ntfs_get_progress_report(void *info) {
    (void) info;
    return (Scan_Progress_Report) {0};
}
