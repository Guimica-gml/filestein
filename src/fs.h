#ifndef FS_H_
#define FS_H_

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _LARGEFILE64_SOURCE
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <threads.h>

#include "./arena.h"

#ifdef _WIN32
#include "./smh_windows.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
typedef HANDLE Fs_Device;
typedef HANDLE Fs_Mutex;
typedef HANDLE Fs_Thread;
typedef DWORD Fs_Thread_Result;
#define FS_THREAD_RESULT_OK 0
#else
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <pthread.h>
typedef int Fs_Device;
typedef pthread_mutex_t Fs_Mutex;
typedef pthread_t Fs_Thread;
typedef void *Fs_Thread_Result;
#define FS_THREAD_RESULT_OK NULL
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define FS_ERROR_BUF_CAP 2048
extern thread_local char fs_error_buf[FS_ERROR_BUF_CAP];

typedef enum {
    FS_MOUNT_POINT_EXT4,
    FS_MOUNT_POINT_NTFS,
} Fs_Mount_Point_Type;

// TODO(nic): make this arena allocatable
#define FS_PATH_CAP 2048
typedef struct {
    char path[FS_PATH_CAP];
    char device_path[FS_PATH_CAP];
    Fs_Mount_Point_Type type;
} Fs_Mount_Point;

typedef struct {
    Fs_Mount_Point *items;
    size_t count;
    size_t capacity;
} Fs_Mount_Points;

bool fs_get_mount_points(Arena *arena, Fs_Mount_Points *mount_points);

bool fs_is_device_valid(Fs_Device *device);
bool fs_open_device(Fs_Device *device, Fs_Mount_Point *mount_point);
int64_t fs_read_device(Fs_Device *device, void *buf, size_t count);
int64_t fs_read_device_off(Fs_Device *device, void *buf, size_t count, size_t offset);
bool fs_set_device_offset(Fs_Device *device, size_t offset);
bool fs_close_device(Fs_Device *device);

typedef Fs_Thread_Result (Fs_Thread_Routine)(void *);

bool fs_spawn_thread(Fs_Thread *thread, Fs_Thread_Routine routine, void *data);
bool fs_wait_thread(Fs_Thread *thread);

bool fs_create_mutex(Fs_Mutex *mutex);
bool fs_lock_mutex(Fs_Mutex *mutex);
bool fs_unlock_mutex(Fs_Mutex *mutex);
bool fs_free_mutex(Fs_Mutex *mutex);

bool fs_get_volume_size(Fs_Device *device, size_t *volume_size);
size_t fs_get_cpu_count(void);

const char *fs_get_last_error(void);

#endif // FS_H_
