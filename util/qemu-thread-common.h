/*
 * Common qemu-thread implementation header file.
 *
 * Copyright Red Hat, Inc. 2018
 *
 * Authors:
 *  Peter Xu <peterx@redhat.com>,
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_THREAD_COMMON_H
#define QEMU_THREAD_COMMON_H

#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#include "qemu/thread.h"
#include "trace.h"

static inline void qemu_mutex_post_init(QemuMutex *mutex)
{
#ifdef CONFIG_DEBUG_MUTEX
    mutex->file = NULL;
    mutex->line = 0;
#endif
    mutex->initialized = true;
}

static inline void qemu_mutex_pre_lock(QemuMutex *mutex,
                                       const char *file, int line)
{
    // if (gettid() > 112 && (long)mutex < 0x700000000000)
        // printf("%d:%lx %s %d %s\n", gettid(), (long)mutex, file, line, __func__);
    trace_qemu_mutex_lock(mutex, file, line);
}

static inline void qemu_mutex_post_lock(QemuMutex *mutex,
                                        const char *file, int line)
{
#ifdef CONFIG_DEBUG_MUTEX
    mutex->file = file;
    mutex->line = line;
#endif
    // if (gettid() > 112 && (long)mutex < 0x700000000000)
        // printf("%d:%lx %s %d %s\n", gettid(), (long)mutex, file, line, __func__);
    trace_qemu_mutex_locked(mutex, file, line);
}

static inline void qemu_mutex_pre_unlock(QemuMutex *mutex,
                                         const char *file, int line)
{
#ifdef CONFIG_DEBUG_MUTEX
    mutex->file = NULL;
    mutex->line = 0;
#endif
    // if (gettid() > 112 && (long)mutex < 0x700000000000)
        // printf("%d:%lx %s %d %s\n", gettid(), (long)mutex, file, line, __func__);
    trace_qemu_mutex_unlock(mutex, file, line);
}

#endif
