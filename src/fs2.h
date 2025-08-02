#ifndef FS_H_
#define FS_H_

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _LARGEFILE64_SOURCE
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "./arena.h"

#ifdef _WIN32
#include <windows.h>
typedef HANDLE Fs_Handle;
typedef HANDLE Fs_Mutex;
typedef HANDLE Fs_Thread;
#else
#include <pthread.h>
typedef int Fs_Handle;
typedef pthread_mutex_t Fs_Mutex;
typedef pthread_t Fs_Thread;
#endif

// TODO(nic): make this arena allocatable
#define FS_PATH_CAP 2048
typedef struct {
    char path[FS_PATH_CAP];
    char device_path[FS_PATH_CAP];
} Fs_Mount_Point;

typedef struct {
    Fs_Mount_Point *items;
    size_t count;
    size_t capacity;
} Fs_Mount_Points;

typedef struct {
    Fs_Handle handle;
    Fs_Mutex mutex;
} Fs_Device;

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points);

bool fs_open_device(Fs_Device *device, Fs_Mount_Point *mount_point);
int64_t fs_read_device(Fs_Device *device, void *buf, size_t count);
int64_t fs_read_device_off(Fs_Device *device, void *buf, size_t count, size_t offset);
bool fs_set_device_offset(Fs_Device *device, size_t offset);
bool fs_close_device(Fs_Device *device);

typedef void *(Fs_Thread_Routine)(void *);
typedef DWORD (Fs_Win32_Thread_Routine)(void *);

bool fs_spawn_thread(Fs_Thread *thread, Fs_Thread_Routine routine, void *data);
bool fs_wait_thread(Fs_Thread *thread);

bool fs_create_mutex(Fs_Mutex *mutex);
void fs_lock_mutex(Fs_Mutex *mutex);
void fs_unlock_mutex(Fs_Mutex *mutex);
bool fs_free_mutex(Fs_Mutex *mutex);

#endif // FS_H_
