#include "./fs2.h"
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
        Nob_String_View type = nob_sv_chop_by_delim(&sv, ' ');
        if (!nob_sv_eq(type, nob_sv_from_cstr("ext4"))) {
            continue;
        }

        Fs_Mount_Point mount_point = {0};
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

bool fs_open_device(Fs_Device *device, Fs_Mount_Point *mount_point) {
    if (!fs_create_mutex(&device->mutex)) {
        return false;
    }
#ifdef _WIN32
    device->handle = CreateFile(
        mount_point->device_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        NULL
    );
    return device->handle != INVALID_HANDLE_VALUE;
#else
    device->handle = open(mount_point->device_path, O_RDONLY | O_LARGEFILE);
    return device->handle != NULL;
#endif
}

int64_t fs_read_device(Fs_Device *device, void *buf, size_t count) {
    int64_t result = 0;
    fs_lock_mutex(&device->mutex);
#ifdef _WIN32
    DWORD rd;
    if (!ReadFile(device->handle, buf, count, &rd, NULL)) {
        nob_return_defer(-1);
    }
    result = (int64_t)rd;
#else
    result = read(device->handle, buf, count);
#endif
defer:
    fs_unlock_mutex(&device->mutex);
    return result;
}

int64_t fs_read_device_off(Fs_Device *device, void *buf, size_t count, size_t offset) {
    if (!fs_set_device_offset(device, offset)) {
        return -1;
    }
    return fs_read_device(device, buf, count);
}

bool fs_set_device_offset(Fs_Device *device, size_t offset) {
    int64_t result;
    fs_lock_mutex(&device->mutex);
#ifdef _WIN32
    result = SetFilePointer(device->handle, offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
#else
    result = lseek64(device->handle, offset, SEEK_SET) >= 0;
#endif
    fs_unlock_mutex(&device->mutex);
    return result;
}

bool fs_close_device(Fs_Device *device) {
    fs_free_mutex(device->mutex);
#ifdef _WIN32
    return CloseHandle(device->handle);
#else
    return close(device->handle) >= 0;
#endif
}

bool fs_spawn_thread(Fs_Thread *thread, Fs_Thread_Routine routine, void *data) {
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, (void*)routine, data, 0, NULL);
    return *thread != NULL;
#else
    return pthread_create(thread, NULL, routine, data) >= 0;
#endif
}

bool fs_wait_thread(Fs_Thread *thread) {
#ifdef _WIN32
    return WaitForSingleObject(thread, INFINITE) != WAIT_FAILED;
#else
    return pthread_join(*thread, NULL) >= 0;
#endif
}

bool fs_create_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    *mutex = CreateMutex(NULL, false, NULL);
    return *mutex != NULL;
#else
    return pthread_mutex_init(mutex, NULL) >= 0;
#endif
}

void fs_lock_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    WaitForSingleObject(*mutex, INFINITE);
#else
    pthread_mutex_lock(mutex);
#endif
}

void fs_unlock_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    ReleaseMutex(*mutex);
#else
    pthread_mutex_unlock(mutex);
#endif
}

bool fs_free_mutex(Fs_Mutex *mutex) {
#ifdef _WIN32
    return CloseHandle(*mutex);
#else
    return pthread_mutex_destroy(mutex) >= 0;
#endif
}
