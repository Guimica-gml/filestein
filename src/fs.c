#include "./fs.h"
#include "./nob.h"

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points) {
#ifdef _WIN32
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
            mount_point.type = FS_MOUNT_POINT_NTFS;
            strcpy(mount_point.path, volume_letter);
            memcpy(mount_point.device_path, buffer, strlen(buffer) - 1);
            arena_da_append(arena, mount_points, mount_point);
        }
    } while (FindNextVolume(first_vol, buffer, FS_PATH_CAP));

    FindVolumeClose(first_vol);
    return true;
#else
    bool result = true;
    const char *mounts_filepath = "/proc/mounts";

    FILE *file = fopen(mounts_filepath, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: could not open `%s`: %s\n", mounts_filepath, strerror(errno));
        nob_return_defer(false);
    }

#define BUFFER_CAP 2048
    char buffer[BUFFER_CAP] = {0};
    while (fgets(buffer, BUFFER_CAP, file) != NULL) {
        Nob_String_View sv = { strlen(buffer), buffer };

        Nob_String_View device_path = nob_sv_chop_by_delim(&sv, ' ');
        if (device_path.count <= 0 || *device_path.data != '/') {
            continue;
        }

        Nob_String_View path = nob_sv_chop_by_delim(&sv, ' ');
        Nob_String_View type_sv = nob_sv_chop_by_delim(&sv, ' ');

        // TODO(nic): kind of a hack
        Fs_Mount_Point_Type type;
        if (nob_sv_eq(type_sv, nob_sv_from_cstr("ext4"))) {
            type = FS_MOUNT_POINT_EXT4;
        } else if (nob_sv_eq(type_sv, nob_sv_from_cstr("fuseblk"))) {
            type = FS_MOUNT_POINT_NTFS;
        } else {
            continue;
        }

        Fs_Mount_Point mount_point = {0};
        mount_point.type = type;
        memcpy(mount_point.path, path.data, min(path.count, FS_PATH_CAP));
        memcpy(mount_point.device_path, device_path.data, min(device_path.count, FS_PATH_CAP));

        arena_da_append(arena, mount_points, mount_point);
    }
#undef BUFFER_CAP

defer:
    if (file) fclose(file);
    return result;
#endif
}

bool fs_is_device_valid(Fs_Device *device) {
#ifdef _WIN32
    return *device != INVALID_HANDLE_VALUE;
#else
    return *device == 0;
#endif
}

bool fs_open_device(Fs_Device *device, Fs_Mount_Point *mount_point) {
#ifdef _WIN32
    *device = CreateFile(
        mount_point->device_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    return *device != INVALID_HANDLE_VALUE;
#else
    *device = open(mount_point->device_path, O_RDONLY | O_LARGEFILE);
    return *device >= 0;
#endif
}

int64_t fs_read_device(Fs_Device *device, void *buf, size_t count) {
#ifdef _WIN32
    DWORD bytes_read;
    if (!ReadFile(*device, buf, count, &bytes_read, NULL)) {
        return -1;
    }
    return (int64_t)bytes_read;
#else
    return read(*device, buf, count);
#endif
}

int64_t fs_read_device_off(Fs_Device *device, void *buf, size_t count, size_t offset) {
#ifdef _WIN32
#define PAGE_SIZE 512
    size_t first_page = offset / PAGE_SIZE;
    size_t last_page = ((offset + count) / PAGE_SIZE) + 1;
    size_t page_count = last_page - first_page;

    unsigned char *temp = malloc(page_count * PAGE_SIZE);
    assert(temp != NULL);

    size_t page_offset = first_page * PAGE_SIZE;
    OVERLAPPED overlapped = {0};
    overlapped.Offset = (DWORD)(page_offset & 0x00000000FFFFFFFF);
    overlapped.OffsetHigh = (DWORD)(page_offset >> 32);

    DWORD bytes_read;
    if (!ReadFile(*device, temp, page_count * PAGE_SIZE, &bytes_read, &overlapped)) {
        DWORD err = GetLastError();
        if (err != ERROR_HANDLE_EOF) {
            free(temp);
            return -1;
        }
        SetLastError(0);
    }

    size_t local_offset = offset - (first_page * PAGE_SIZE);
    size_t actual_bytes_count = min(count, bytes_read - local_offset);
    memcpy(buf, &temp[local_offset], actual_bytes_count);

    free(temp);
    return (int64_t)actual_bytes_count;
#undef PAGE_SIZE
#else
    return pread(*device, buf, count, offset);
#endif
}

bool fs_set_device_offset(Fs_Device *device, size_t offset) {
#ifdef _WIN32
    return SetFilePointer(*device, offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
#else
    return lseek64(*device, offset, SEEK_SET) >= 0;
#endif
}

bool fs_close_device(Fs_Device *device) {
#ifdef _WIN32
    return CloseHandle(*device);
#else
    return close(*device) == 0;
#endif
}

bool fs_spawn_thread(Fs_Thread *thread, Fs_Thread_Routine routine, void *data) {
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, routine, data, 0, NULL);
    return *thread != NULL;
#else
    errno = pthread_create(thread, NULL, routine, data);
    return errno == 0;
#endif
}

bool fs_wait_thread(Fs_Thread *thread) {
#ifdef _WIN32
    return WaitForSingleObject(*thread, INFINITE) != WAIT_FAILED;
#else
    errno = pthread_join(*thread, NULL);
    return errno == 0;
#endif
}

bool fs_create_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    *mutex = CreateMutex(NULL, false, NULL);
    return *mutex != NULL;
#else
    errno = pthread_mutex_init(mutex, NULL);
    return errno == 0;
#endif
}

bool fs_lock_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    return WaitForSingleObject(*mutex, INFINITE) != WAIT_FAILED;
#else
    errno = pthread_mutex_lock(mutex);
    return errno == 0;
#endif
}

bool fs_unlock_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    return ReleaseMutex(*mutex);
#else
    errno = pthread_mutex_unlock(mutex);
    return errno == 0;
#endif
}

bool fs_free_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    return CloseHandle(*mutex);
#else
    errno = pthread_mutex_destroy(mutex);
    return errno == 0;
#endif
}

bool fs_get_volume_size(Fs_Device *device, size_t *volume_size) {
#ifdef _WIN32
    GET_LENGTH_INFORMATION disk_length_info;
    DWORD bytes_returned;
    if (!DeviceIoControl(*device, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &disk_length_info, sizeof(GET_LENGTH_INFORMATION), &bytes_returned, NULL)) {
        return false;
    }
    *volume_size = disk_length_info.Length.QuadPart;
    return true;
#else
    return ioctl(*device, BLKGETSIZE64, volume_size) == 0;
#endif
}

size_t fs_get_cpu_count(void) {
#ifdef _WIN32
    DWORD cpu_count = GetCurrentProcessorNumber();
    return max(1, cpu_count);
#else
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    return max(1, cpu_count);
#endif
}

thread_local char fs_error_buf[FS_ERROR_BUF_CAP] = {0};

const char *fs_get_last_error(void) {
#ifdef _WIN32
    DWORD error_code = GetLastError();
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        fs_error_buf, FS_ERROR_BUF_CAP, NULL
    );
    return fs_error_buf;
#else
    strncpy(fs_error_buf, strerror(errno), FS_ERROR_BUF_CAP);
    return fs_error_buf;
#endif
}
