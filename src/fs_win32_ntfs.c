#include "./fs.h"
#include "./nob.h"
#include "./ntfs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points) {
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
            Fs_Mount_Point mount_point = {0};
            strcpy(mount_point.path, volume_letter);
            memcpy(mount_point.device_path, buffer, strlen(buffer) - 1);
            arena_da_append(arena, mount_points, mount_point);
        }
    } while (FindNextVolume(first_vol, buffer, FS_PATH_CAP));

    FindVolumeClose(first_vol);
    return true;
}

void *fs_scan_mount_point(Arena *arena, Fs_Mount_Point *mount_point, Fs_Files *files) {
    void *result = NULL;
    HANDLE device = CreateFile(mount_point->device_path,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                               NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: could not open device: %lu\n", GetLastError());
        nob_return_defer(NULL);
    }

    struct ntfs_pbs pbs = {0};

    DWORD rd;
    if (!ReadFile(device, &pbs, sizeof(pbs), &rd, NULL)) {
        fprintf(stderr, "Error: could not read device: %lu\n", GetLastError());
        nob_return_defer(NULL);
    }
    fs_hexdump(&pbs, sizeof(pbs), 0);

    printf("-------------\n");
    printf("magic: 0x%08zX\n", pbs.magic);
    printf("bytes per sector: %d\n", pbs.bytes_per_sector);
    printf("sectors per cluster: %d\n", pbs.sectors_per_cluster);
    printf("mft cluster number: %lld\n", pbs.mft_cluster_number);
    fflush(stderr);
    fflush(stdout);

    int32_t mft_offset = pbs.mft_cluster_number * pbs.sectors_per_cluster * pbs.bytes_per_sector;
    if (SetFilePointer(device, mft_offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Error: could not set file pointer: %lu\n", GetLastError());
        nob_return_defer(NULL);
    }
    fflush(stderr);
    fflush(stdout);

    printf("-------------\n");
    unsigned char buf[1024];
    if (!ReadFile(device, buf, sizeof(buf), &rd, NULL)) {
        fprintf(stderr, "Error: could not read device: %lu\n", GetLastError());
        nob_return_defer(NULL);
    }
    fs_hexdump(buf, sizeof(buf), 0);
    fflush(stderr);
    fflush(stdout);

defer:
    if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
    return result;
}

Fs_Progress_Report fs_scan_get_progress_report(void *id) {
    (void) id;
    return (Fs_Progress_Report) {0};
}
