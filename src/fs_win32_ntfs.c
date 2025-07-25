#include "./fs.h"
#include "./nob.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define BUFFER_CAP 2048

void add_volume_info(struct fs_mount_points *mount_points, const char *volume_path) {
    char volume_letter[BUFFER_CAP] = {0};
    unsigned long int volume_letter_size;
    if (!GetVolumePathNamesForVolumeName(volume_path, volume_letter, BUFFER_CAP, &volume_letter_size)) {
        return;
    }
    assert(volume_letter_size <= BUFFER_CAP);

    char fs_type[BUFFER_CAP] = {0};
    if (!GetVolumeInformation(volume_letter, NULL, 0, NULL, NULL, NULL, fs_type, BUFFER_CAP)) {
        return;
    }

    if (strcmp(fs_type, "NTFS") == 0) {
        struct fs_mount_point mount_point = {0};
        strcpy(mount_point.path, volume_letter);
        strcpy(mount_point.device_path, volume_path);
        nob_da_append(mount_points, mount_point);
    }
}

bool fs_get_mount_points(struct fs_mount_points *mount_points) {
    char buffer[BUFFER_CAP] = {0};

    HANDLE first_vol = FindFirstVolume(buffer, BUFFER_CAP);
    if (first_vol == INVALID_HANDLE_VALUE) {
        return false;
    }

    add_volume_info(mount_points, buffer);
    while (FindNextVolume(first_vol, buffer, BUFFER_CAP)) {
        add_volume_info(mount_points, buffer);
    }

    FindVolumeClose(first_vol);
    return true;
}

#undef BUFFER_CAP

#define SECTOR_SIZE 512

bool fs_scan_mount_point(struct fs_mount_point *mount_point, struct fs_files *files) {
    HANDLE device = CreateFile(mount_point->device_path,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Could not open file: %lu\n", GetLastError());
        return false;
    }

    unsigned char buf[SECTOR_SIZE];
    DWORD rd;
    if (!ReadFile(device, buf, SECTOR_SIZE, &rd, NULL)) {
        fprintf(stderr, "Could not read file: %lu\n", GetLastError());
        CloseHandle(device);
        return false;
    }

    for (size_t i = 0; i < SECTOR_SIZE; i++) {
        printf("%X ", buf[i]);
    }

    CloseHandle(device);
    return true;
}
