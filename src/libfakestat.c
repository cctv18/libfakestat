// SPDX-License-Identifier: Apache-2.0

/*
 * libfakestat: A trick on timestamp acquisition for Unix/Linux programs.
 * Copyright (c) 2025 cctv18
 *
 * *Usage example:
 * [e.g.] export FAKESTAT="2025-10-18 14:30:00"
 * [e.g.] LD_PRELOAD=./libfakestat.so ls -l --full-time
 *
 * [Optional] WORKPATH and NWORKPATH: 
 * Only apply to paths containing WORKPATH and 
 * excluding paths containing NWORKPATH (higher priority).
 * Support wildcard characters (* and?) to match paths.
 * [e.g.] export WORKPATH="/my/project foo.c"
 * [e.g.] NWORKPATH="/my/project/out bar.o"
 * [e.g.] export NWORKPATH="*.o *.so"
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <limits.h>
#include <fnmatch.h>

// --- Global variables to store our fake time ---
static time_t g_fake_time_t = 0;
static struct timespec g_fake_timespec = {0, 0};
static struct statx_timestamp g_fake_timestamp = {0, 0};

static char **g_workpaths = NULL;
static int g_workpaths_count = 0;
static char *g_workpath_strdup = NULL;

static char **g_nworkpaths = NULL;
static int g_nworkpaths_count = 0;
static char *g_nworkpath_strdup = NULL;

// --- Reentrancy protection ---
// (preventing __xstat -> real_xstat -> ... -> __xstat)
static __thread bool g_dont_fake_stat = false;

// Guard macro to set the "do not hijack" flag when calling the real function
#define DONT_FAKE_STAT(call) \
  do { \
    bool old_val = g_dont_fake_stat; \
    g_dont_fake_stat = true; \
    call; \
    g_dont_fake_stat = old_val; \
  } while (0)

typedef int (*real_xstat_f_t)(int ver, const char *path, struct stat *stat_buf);
typedef int (*real_lxstat_f_t)(int ver, const char *path, struct stat *stat_buf);
typedef int (*real_fxstat_f_t)(int ver, int fd, struct stat *stat_buf);
typedef int (*real_fxstatat_f_t)(int ver, int dirfd, const char *path, struct stat *stat_buf, int flags);
typedef int (*real_statx_f_t)(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);

static real_xstat_f_t real_xstat = NULL;
static real_lxstat_f_t real_lxstat = NULL;
static real_fxstat_f_t real_fxstat = NULL;
static real_fxstatat_f_t real_fxstatat = NULL;
static real_statx_f_t real_statx = NULL;

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static bool check_missing_real(const char *name, bool missing) {
    if (missing) {
        // fprintf(stderr, "libfakestat: problem: original %s not found.\n", name);
        return false;
    }
    return true;
}
#define CHECK_MISSING_REAL(name) \
  check_missing_real(#name, (NULL == real_##name))

static void parse_path_list(const char *env_str, char ***path_list_out, int *count_out, char **strdup_out) {
    if (!env_str || *env_str == '\0') {
        *path_list_out = NULL;
        *count_out = 0;
        *strdup_out = NULL;
        return;
    }

    *strdup_out = strdup(env_str);
    if (!*strdup_out) {
        fprintf(stderr, "libfakestat: strdup 内存分配失败\n");
        *path_list_out = NULL;
        *count_out = 0;
        return;
    }

    *path_list_out = NULL;
    *count_out = 0;
    const char *delim = " ";
    char *p = strtok(*strdup_out, delim);

    while (p) {
        (*count_out)++;
        char **new_list = (char**)realloc(*path_list_out, (*count_out) * sizeof(char*));
        if (!new_list) {
            fprintf(stderr, "libfakestat: realloc 内存分配失败\n");
            free(*path_list_out);
            *path_list_out = NULL;
            *count_out = 0;
            return; 
        }
        *path_list_out = new_list;
        (*path_list_out)[*count_out - 1] = p;
        p = strtok(NULL, delim);
    }
}

static void ft_stat_init(void) {
    const char *fakestat_str = getenv("FAKESTAT");
    g_fake_time_t = 0; // --> Default time: 1970-01-01 00:00:00

    if (fakestat_str) {
        struct tm tm_struct;
        memset(&tm_struct, 0, sizeof(struct tm));
        
        int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;

        int items_parsed = sscanf(fakestat_str, "%d-%d-%d %d:%d:%d", 
                                  &year, &month, &day, &hour, &min, &sec);

        if (items_parsed == 3) {
            // hh:mm:ss has been set to default (00:00:00)
        } else if (items_parsed != 6) {
            fprintf(stderr, 
                    "libfakestat: FAKESTAT 格式无效 '%s' (应为 'YYYY-MM-DD hh:mm:ss' 或 'YYYY-MM-DD')。\n"
                    "libfakestat: 将使用默认时间 1970-01-01 00:00:00。\n", fakestat_str);
            g_fake_time_t = 0;
        }

        if (items_parsed == 3 || items_parsed == 6) {
            tm_struct.tm_year = year - 1900;
            tm_struct.tm_mon = month - 1;
            tm_struct.tm_mday = day;
            tm_struct.tm_hour = hour;
            tm_struct.tm_min = min;
            tm_struct.tm_sec = sec;
            tm_struct.tm_isdst = -1;

            g_fake_time_t = mktime(&tm_struct);
            if (g_fake_time_t == -1) {
                fprintf(stderr, "libfakestat: mktime() 转换 FAKESTAT 失败。\n");
                g_fake_time_t = 0;
            }
        }
    }

    // Set up all global time structures
    g_fake_timespec.tv_sec = g_fake_time_t;
    g_fake_timespec.tv_nsec = 0;
    g_fake_timestamp.tv_sec = g_fake_time_t;
    g_fake_timestamp.tv_nsec = 0;

    // Parsing WORKPATH and NWORKPATH
    const char *workpath_env = getenv("WORKPATH");
    const char *nworkpath_env = getenv("NWORKPATH");
    parse_path_list(workpath_env, &g_workpaths, &g_workpaths_count, &g_workpath_strdup);
    parse_path_list(nworkpath_env, &g_nworkpaths, &g_nworkpaths_count, &g_nworkpath_strdup);

    // Find all real function pointers
    // We set g_dont_fake_stat to prevent dlsym from triggering stat internally.
    g_dont_fake_stat = true;
    real_xstat = dlsym(RTLD_NEXT, "__xstat");
    real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    real_fxstat = dlsym(RTLD_NEXT, "__fxstat");
    real_fxstatat = dlsym(RTLD_NEXT, "__fxstatat");
    real_statx = dlsym(RTLD_NEXT, "statx");
    g_dont_fake_stat = false;
}

__attribute__((destructor))
static void ft_stat_cleanup(void) {
    if (g_workpath_strdup) free(g_workpath_strdup);
    if (g_nworkpath_strdup) free(g_nworkpath_strdup);
    if (g_workpaths) free(g_workpaths);
    if (g_nworkpaths) free(g_nworkpaths);
}

static void apply_fake_stat(struct stat *stat_buf) {
    stat_buf->st_atim = g_fake_timespec;
    stat_buf->st_mtim = g_fake_timespec;
    stat_buf->st_ctim = g_fake_timespec;
}

static void apply_fake_statx(struct statx *statx_buf) {
    statx_buf->stx_atime = g_fake_timestamp;
    statx_buf->stx_mtime = g_fake_timestamp;
    statx_buf->stx_ctime = g_fake_timestamp;
    statx_buf->stx_btime = g_fake_timestamp;
    statx_buf->stx_mask |= (STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_BTIME);
}

/**
 * Checking if the files under given path should be faked
 */
static bool should_fake_path(const char *path) {
    if (path == NULL) {
        if (g_workpaths_count > 0) {
            return false;
        }
        return true;
    }

    // Get the absolute file path
    char resolved_buf[PATH_MAX];
    const char *path_to_check = path; 

    DONT_FAKE_STAT({
        if (realpath(path, resolved_buf)) {
            path_to_check = resolved_buf; // If successful, use the absolute path
        }
    });

    bool matches_nworkpath = false;
    bool matches_workpath = false;
    
    // Buffer for building fnmatch patterns
    // +2 for leading and trailing '*', +1 for '\0'
    char pattern_buf[PATH_MAX + 3];

    // Check NWORKPATH (highest priority)
    if (g_nworkpaths_count > 0) {
        for (int i = 0; i < g_nworkpaths_count; i++) {
            if (g_nworkpaths[i]) {
                // Automatically wrap path pattern as *pattern*
                snprintf(pattern_buf, sizeof(pattern_buf), "*%s*", g_nworkpaths[i]);
                
                // fnmatch(pattern, string, flags)
                // flags=0 means '*' , can also match '/'
                if (fnmatch(pattern_buf, path_to_check, 0) == 0) {
                    matches_nworkpath = true;
                    break;
                }
            }
        }
    }
    
    if (matches_nworkpath) {
        return false; // Match exclusion list, no faking
    }

    // Check WORKPATH (if NWORKPATH non-match)
    if (g_workpaths_count > 0) {
        for (int i = 0; i < g_workpaths_count; i++) {
             if (g_workpaths[i]) {
                // Automatically wrap path pattern as *pattern*
                snprintf(pattern_buf, sizeof(pattern_buf), "*%s*", g_workpaths[i]);

                if (fnmatch(pattern_buf, path_to_check, 0) == 0) {
                    matches_workpath = true;
                    break;
                }
            }
        }
        return matches_workpath; // Fake only if the path matches
    }

    // 5. Default (no WORKPATH or NWORKPATH matches)
    return true; 
}


// --- Hijack stat, lstat, fstat, fstatat ---

// Hijack stat() -> __xstat()
int __xstat(int ver, const char *path, struct stat *stat_buf) {
    pthread_once(&g_init_once, ft_stat_init);
    if (!CHECK_MISSING_REAL(xstat)) return -1;
    int ret;
    DONT_FAKE_STAT(ret = real_xstat(ver, path, stat_buf));
    if (ret == 0 && !g_dont_fake_stat && should_fake_path(path)) {
        apply_fake_stat(stat_buf);
    }
    return ret;
}

// Hijack lstat() -> __lxstat()
int __lxstat(int ver, const char *path, struct stat *stat_buf) {
    pthread_once(&g_init_once, ft_stat_init);
    if (!CHECK_MISSING_REAL(lxstat)) return -1;
    int ret;
    DONT_FAKE_STAT(ret = real_lxstat(ver, path, stat_buf));
    if (ret == 0 && !g_dont_fake_stat && should_fake_path(path)) {
        apply_fake_stat(stat_buf);
    }
    return ret;
}

// Hijack fstat() -> __fxstat()
int __fxstat(int ver, int fd, struct stat *stat_buf) {
    pthread_once(&g_init_once, ft_stat_init);
    if (!CHECK_MISSING_REAL(fxstat)) return -1;
    int ret;
    DONT_FAKE_STAT(ret = real_fxstat(ver, fd, stat_buf));
    if (ret == 0 && !g_dont_fake_stat && should_fake_path(NULL)) {
        apply_fake_stat(stat_buf);
    }
    return ret;
}

// Hijack fstatat() -> __fxstatat()
int __fxstatat(int ver, int dirfd, const char *path, struct stat *stat_buf, int flags) {
    pthread_once(&g_init_once, ft_stat_init);
    if (!CHECK_MISSING_REAL(fxstatat)) return -1;
    int ret;
    DONT_FAKE_STAT(ret = real_fxstatat(ver, dirfd, path, stat_buf, flags));
    if (ret == 0 && !g_dont_fake_stat && should_fake_path(path)) {
        apply_fake_stat(stat_buf);
    }
    return ret;
}

// --- Hijack statx (to hijack crtime)---
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    pthread_once(&g_init_once, ft_stat_init);
    if (!CHECK_MISSING_REAL(statx)) return -1;
    int ret;
    DONT_FAKE_STAT(ret = real_statx(dirfd, pathname, flags, mask, statxbuf));
    if (ret == 0 && !g_dont_fake_stat && should_fake_path(pathname)) {
        apply_fake_statx(statxbuf);
    }
    return ret;
}
