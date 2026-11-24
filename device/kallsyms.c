#define _GNU_SOURCE
#include "device_common.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ==========================================================================
 * 1. /proc/kallsyms ThinLTO Resolver (<sym> or <sym>.llvm.<hash>)
 * ========================================================================== */

struct ksym_item {
    char *name;
    char  type;
};

struct ksym_db {
    struct ksym_item *items;
    size_t            count;
    size_t            cap;
};

static bool is_func_sym_type(char t) {
    return t == 't' || t == 'T' || t == 'w' || t == 'W';
}

struct ksym_db *ksym_db_load(const char *path, char *err_buf, size_t err_cap) {
    const char *p = path ? path : "/proc/kallsyms";
    FILE *fp = fopen(p, "r");
    if (!fp) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "fopen(%s) failed: %s", p, strerror(errno));
        return NULL;
    }

    struct ksym_db *db = calloc(1, sizeof(*db));
    if (!db) {
        fclose(fp);
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory for ksym_db");
        return NULL;
    }
    db->cap = 65536;
    db->items = malloc(db->cap * sizeof(struct ksym_item));
    if (!db->items) {
        free(db);
        fclose(fp);
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory for ksym items");
        return NULL;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char addr_s[64], type_s[8], sym_s[256];
        if (sscanf(line, "%63s %7s %255s", addr_s, type_s, sym_s) != 3)
            continue;
        char t = type_s[0];
        if (!is_func_sym_type(t))
            continue;

        if (db->count == db->cap) {
            size_t ncap = db->cap * 2U;
            struct ksym_item *nitems = realloc(db->items, ncap * sizeof(struct ksym_item));
            if (!nitems) break;
            db->items = nitems;
            db->cap = ncap;
        }
        char *dup = strdup(sym_s);
        if (!dup) break;
        db->items[db->count].name = dup;
        db->items[db->count].type = t;
        db->count++;
    }
    fclose(fp);

    if (db->count == 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "no function symbols found in %s", p);
        ksym_db_free(db);
        return NULL;
    }
    return db;
}

void ksym_db_free(struct ksym_db *db) {
    if (!db) return;
    for (size_t i = 0; i < db->count; i++)
        free(db->items[i].name);
    free(db->items);
    free(db);
}

int ksym_resolve(const struct ksym_db *db, const char *base_sym,
                 char *resolved_out, size_t resolved_cap) {
    if (!db || !base_sym || !resolved_out || resolved_cap == 0) return -1;
    size_t blen = strlen(base_sym);

    /* 1. Exact match preferred */
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->items[i].name, base_sym) == 0) {
            snprintf(resolved_out, resolved_cap, "%s", base_sym);
            return 0;
        }
    }

    /* 2. ThinLTO <sym>.llvm.<hash> match (fail closed on distinct ambiguity) */
    const char *matched = NULL;
    for (size_t i = 0; i < db->count; i++) {
        const char *s = db->items[i].name;
        if (strncmp(s, base_sym, blen) == 0 && strncmp(s + blen, ".llvm.", 6) == 0) {
            /* Also strip any further .cfi_jt suffix: kprobes attach to function entry, not jump table */
            if (strstr(s + blen, ".cfi")) continue;
            if (!matched) {
                matched = s;
            } else if (strcmp(matched, s) != 0) {
                return -2; /* ambiguous static symbol across multiple TUs */
            }
        }
    }

    if (matched) {
        snprintf(resolved_out, resolved_cap, "%s", matched);
        return 0;
    }
    return -1;
}

/* ==========================================================================
 * 2. Tracefs Root, Boot ID, State File & Stale Kprobe Group Reaper
 * ========================================================================== */

const char *tracefs_root(void) {
    static const char *cached = NULL;
    if (cached) return cached;
    if (access("/sys/kernel/tracing/events", F_OK) == 0) {
        cached = "/sys/kernel/tracing";
    } else if (access("/sys/kernel/debug/tracing/events", F_OK) == 0) {
        cached = "/sys/kernel/debug/tracing";
    } else {
        cached = "/sys/kernel/tracing";
    }
    return cached;
}

int read_boot_id(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    out[0] = '\0';
    FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!fp) return -1;
    if (!fgets(out, (int)cap, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r' || out[len - 1] == ' '))
        out[--len] = '\0';
    return len > 0 ? 0 : -1;
}

static const char *state_dir_path(void) {
    struct stat st;
    if (stat("/data/local/tmp", &st) == 0 && S_ISDIR(st.st_mode) &&
        access("/data/local/tmp", W_OK) == 0) {
        return "/data/local/tmp";
    }
    return "/tmp";
}

static bool pid_is_live_pktpath(pid_t pid) {
    if (pid <= 0) return false;
    if (pid == getpid()) return true;
    if (kill(pid, 0) == -1 && errno == ESRCH)
        return false;

    /* Check /proc/<pid>/comm to guard against PID recycling */
    char cpath[64];
    snprintf(cpath, sizeof(cpath), "/proc/%d/comm", (int)pid);
    FILE *fp = fopen(cpath, "r");
    if (!fp) return true; /* EPERM or transient: be conservative if kill() succeeded */
    char comm[64] = {0};
    if (!fgets(comm, sizeof(comm), fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    return strncmp(comm, "pktpath", 7) == 0;
}

int tracefs_write_state_file(pid_t pid, const char *group_name) {
    char boot_id[64] = "unknown";
    (void)read_boot_id(boot_id, sizeof(boot_id));

    char path[256];
    snprintf(path, sizeof(path), "%s/.pktpath_state_%d", state_dir_path(), (int)pid);
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "pid=%d\nboot_id=%s\ngroup=%s\n", (int)pid, boot_id, group_name ? group_name : "");
    fclose(fp);
    return 0;
}

void tracefs_remove_state_file(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/data/local/tmp/.pktpath_state_%d", (int)pid);
    (void)unlink(path);
    snprintf(path, sizeof(path), "/tmp/.pktpath_state_%d", (int)pid);
    (void)unlink(path);
}

int tracefs_unregister_kprobe(const char *group, const char *event_name) {
    char kp_path[256];
    snprintf(kp_path, sizeof(kp_path), "%s/kprobe_events", tracefs_root());
    int fd = open(kp_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return -1;
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "-:%s/%s\n", group, event_name);
    ssize_t w = write(fd, cmd, (size_t)n);
    close(fd);
    return (w == n) ? 0 : -1;
}

void tracefs_unregister_group_all(const char *group) {
    if (!group || !group[0]) return;
    char kp_path[256];
    snprintf(kp_path, sizeof(kp_path), "%s/kprobe_events", tracefs_root());
    FILE *fp = fopen(kp_path, "r");
    if (!fp) return;

    char needle[128];
    snprintf(needle, sizeof(needle), ":%s/", group);
    size_t nlen = strlen(needle);

    /* Collect event names first so we don't mutate while reading */
    char events[128][96];
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && count < 128) {
        const char *pos = strstr(line, needle);
        if (!pos) continue;
        const char *ev_start = pos + nlen;
        size_t elen = 0;
        while (ev_start[elen] && !isspace((unsigned char)ev_start[elen]) && elen < 95)
            elen++;
        if (elen > 0) {
            memcpy(events[count], ev_start, elen);
            events[count][elen] = '\0';
            count++;
        }
    }
    fclose(fp);

    for (int i = 0; i < count; i++) {
        (void)tracefs_unregister_kprobe(group, events[i]);
    }
}

static void reap_state_dir(const char *dir_path, const char *cur_boot, int *reaped_cnt) {
    DIR *d = opendir(dir_path);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, ".pktpath_state_", 15) != 0)
            continue;
        char full[512];
        snprintf(full, sizeof(full), "%s/%s", dir_path, de->d_name);
        FILE *fp = fopen(full, "r");
        int old_pid = atoi(de->d_name + 15);
        char old_boot[64] = "";
        char old_grp[96] = "";
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                size_t l = strlen(line);
                while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
                if (strncmp(line, "pid=", 4) == 0) old_pid = atoi(line + 4);
                else if (strncmp(line, "boot_id=", 8) == 0) snprintf(old_boot, sizeof(old_boot), "%s", line + 8);
                else if (strncmp(line, "group=", 6) == 0) snprintf(old_grp, sizeof(old_grp), "%s", line + 6);
            }
            fclose(fp);
        }
        bool boot_mismatch = (cur_boot[0] && old_boot[0] && strcmp(cur_boot, old_boot) != 0);
        if (old_pid != (int)getpid() && (boot_mismatch || !pid_is_live_pktpath((pid_t)old_pid))) {
            if (!old_grp[0] && old_pid > 0)
                snprintf(old_grp, sizeof(old_grp), "pktpath_%d", old_pid);
            tracefs_unregister_group_all(old_grp);
            (void)unlink(full);
            (*reaped_cnt)++;
        }
    }
    closedir(d);
}

int tracefs_reap_stale_groups(void) {
    char cur_boot[64] = "";
    (void)read_boot_id(cur_boot, sizeof(cur_boot));
    int reaped = 0;

    /* 1. Reap via .pktpath_state_<pid> markers */
    reap_state_dir("/data/local/tmp", cur_boot, &reaped);
    reap_state_dir("/tmp", cur_boot, &reaped);

    /* 2. Direct scan of kprobe_events for any orphaned pktpath_<oldpid>/... */
    char kp_path[256];
    snprintf(kp_path, sizeof(kp_path), "%s/kprobe_events", tracefs_root());
    FILE *fp = fopen(kp_path, "r");
    if (!fp) return reaped;

    struct {
        char grp[64];
        char ev[96];
    } orphans[128];
    int norph = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && norph < 128) {
        const char *p = strstr(line, ":pktpath_");
        if (!p) continue;
        p++; /* skip ':' -> "pktpath_<pid>/<ev>" */
        const char *slash = strchr(p, '/');
        if (!slash || (size_t)(slash - p) >= sizeof(orphans[0].grp)) continue;

        char grp[64];
        size_t glen = (size_t)(slash - p);
        memcpy(grp, p, glen);
        grp[glen] = '\0';

        int old_pid = atoi(grp + 8);
        if (old_pid > 0 && !pid_is_live_pktpath((pid_t)old_pid)) {
            const char *ev_s = slash + 1;
            size_t elen = 0;
            while (ev_s[elen] && !isspace((unsigned char)ev_s[elen]) && elen < 95)
                elen++;
            if (elen > 0) {
                snprintf(orphans[norph].grp, sizeof(orphans[0].grp), "%s", grp);
                memcpy(orphans[norph].ev, ev_s, elen);
                orphans[norph].ev[elen] = '\0';
                norph++;
            }
        }
    }
    fclose(fp);

    for (int i = 0; i < norph; i++) {
        if (tracefs_unregister_kprobe(orphans[i].grp, orphans[i].ev) == 0)
            reaped++;
    }
    return reaped;
}

int tracefs_register_kprobe(const char *group, const char *event_name,
                            const char *resolved_sym, bool is_retprobe) {
    char kp_path[256];
    snprintf(kp_path, sizeof(kp_path), "%s/kprobe_events", tracefs_root());
    int fd = open(kp_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return -1;

    char cmd[384];
    int n;
    if (is_retprobe) {
        n = snprintf(cmd, sizeof(cmd), "r256:%s/%s %s\n", group, event_name, resolved_sym);
        if (write(fd, cmd, (size_t)n) == n) {
            close(fd);
            return 0;
        }
        /* Fallback to default maxactive if r256: not accepted */
        n = snprintf(cmd, sizeof(cmd), "r:%s/%s %s\n", group, event_name, resolved_sym);
    } else {
        n = snprintf(cmd, sizeof(cmd), "p:%s/%s %s\n", group, event_name, resolved_sym);
    }

    ssize_t w = write(fd, cmd, (size_t)n);
    close(fd);
    return (w == n) ? 0 : -1;
}

bool tracefs_event_exists(const char *category, const char *event_name) {
    char path[256];
    snprintf(path, sizeof(path), "%s/events/%s/%s/id", tracefs_root(), category, event_name);
    return access(path, R_OK) == 0;
}

int tracefs_read_event_id(const char *category, const char *event_name) {
    char path[256];
    snprintf(path, sizeof(path), "%s/events/%s/%s/id", tracefs_root(), category, event_name);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int id = -1;
    if (fscanf(fp, "%d", &id) != 1) id = -1;
    fclose(fp);
    return id;
}

int tracefs_read_kprobe_profile(const char *group_prefix,
                                struct kprobe_miss_entry *out, int max_entries) {
    char path[256];
    snprintf(path, sizeof(path), "%s/kprobe_profile", tracefs_root());
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    size_t plen = group_prefix ? strlen(group_prefix) : 0;
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && count < max_entries) {
        char ev[96];
        unsigned long long nhit = 0, nmissed = 0;
        if (sscanf(line, "%95s %llu %llu", ev, &nhit, &nmissed) != 3)
            continue;
        if (plen > 0 && strncmp(ev, group_prefix, plen) != 0)
            continue;
        snprintf(out[count].event_name, sizeof(out[count].event_name), "%s", ev);
        out[count].nhit = nhit;
        out[count].nmissed = nmissed;
        count++;
    }
    fclose(fp);
    return count;
}
