#include "./fs.h"
#include "./nob.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool fs_get_mount_points(Arena *arena, struct fs_mount_points *mount_points) {
    char buffer[FS_PATH_CAP] = {0};
    HANDLE first_vol = FindFirstVolume(buffer, FS_PATH_CAP);
    if (first_vol == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        char volume_letter[FS_PATH_CAP] = {0};
        unsigned long int volume_letter_size;
        if (!GetVolumePathNamesForVolumeName(buffer, volume_letter, FS_PATH_CAP, &volume_letter_size)) {
            continue;
        }
        assert(volume_letter_size <= FS_PATH_CAP);

        char fs_type[FS_PATH_CAP] = {0};
        if (!GetVolumeInformation(volume_letter, NULL, 0, NULL, NULL, NULL, fs_type, FS_PATH_CAP)) {
            continue;
        }

        if (strcmp(fs_type, "NTFS") == 0) {
            struct fs_mount_point mount_point = {0};
            strcpy(mount_point.path, volume_letter);
            strcpy(mount_point.device_path, buffer);
            arena_da_append(arena, mount_points, mount_point);
        }
    } while (FindNextVolume(first_vol, buffer, FS_PATH_CAP));

    FindVolumeClose(first_vol);
    return true;
}

#define SECTOR_SIZE 512

void *fs_scan_mount_point(Arena *arena, struct fs_mount_point *mount_point, struct fs_files *files) {
    HANDLE device = CreateFile(mount_point->device_path,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: could not open device: %lu\n", GetLastError());
        return NULL;
    }

    unsigned char buf[SECTOR_SIZE];
    DWORD rd;
    if (!ReadFile(device, buf, SECTOR_SIZE, &rd, NULL)) {
        fprintf(stderr, "Error: could not read device: %lu\n", GetLastError());
        CloseHandle(device);
        return NULL;
    }
    fs_hexdump(buf, sizeof(buf), 0);

    CloseHandle(device);
    return NULL;
}

struct fs_progress_report fs_scan_get_progress_report(void *id) {
    (void) id;
    return (struct fs_progress_report) {0};
}
