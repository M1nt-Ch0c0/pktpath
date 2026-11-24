#define _GNU_SOURCE
#include "device_common.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ==========================================================================
 * Pre-existing Long-Lived Socket Warmup (proc_warmup.c)
 * 1. Enumerates live TCP/UDP/ICMP v4/v6 sockets directly via NETLINK_SOCK_DIAG
 *    for exact (inode, 64-bit skc_cookie, uid) — works even under Android
 *    kptr_restrict=2 where /proc/net/{tcp,udp} masks sk_ptr to 0!
 * 2. Optionally enriches kernel sk_ptr (0xFFFF...) from /proc/net/{tcp,udp}
 *    when kptr_restrict < 2.
 * 3. Scans /proc/<pid>/fd -> socket:[inode] + /proc/<pid>/comm for tgid/comm.
 * ========================================================================== */

struct inode_sock_cand {
    uint64_t inode;
    uint64_t sk_ptr;
    uint64_t cookie;
    uint32_t uid;
    uint32_t tgid;
    bool     has_cookie;
    bool     has_owner;
    char     comm[16];
};

static bool is_valid_kernel_sk_ptr(uint64_t ptr) {
    return (ptr & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
           ptr != 0xFFFFFFFFFFFFFFFFULL;
}

static void collect_sock_diag_family(uint8_t family, uint8_t proto, uint32_t seq,
                                     struct inode_sock_cand *cands, int *cnt, int max_cands) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return;
    int rcvbuf = 512 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg;
    memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len = sizeof(msg);
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq = seq;
    msg.req.sdiag_family = family;
    msg.req.sdiag_protocol = proto;
    msg.req.idiag_states = 0xFFFFFFFFU;

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    if (sendto(fd, &msg, sizeof(msg), 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        close(fd);
        return;
    }

    uint8_t buf[32768];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;

        int rem = (int)n;
        for (const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
             NLMSG_OK(nlh, rem);
             nlh = NLMSG_NEXT(nlh, rem)) {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                close(fd);
                return;
            }
            if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
                continue;

            const struct inet_diag_msg *r = (const struct inet_diag_msg *)NLMSG_DATA(nlh);
            uint64_t ino = r->idiag_inode;
            uint64_t ck = ((uint64_t)r->id.idiag_cookie[1] << 32) |
                          (uint64_t)r->id.idiag_cookie[0];
            if (ino == 0 || ck == 0 || ck == ~0ULL)
                continue;

            bool exists = false;
            for (int i = 0; i < *cnt; i++) {
                if (cands[i].inode == ino) {
                    cands[i].cookie = ck;
                    cands[i].uid = r->idiag_uid;
                    cands[i].has_cookie = true;
                    exists = true;
                    break;
                }
            }
            if (!exists && *cnt < max_cands) {
                struct inode_sock_cand *c = &cands[(*cnt)++];
                memset(c, 0, sizeof(*c));
                c->inode = ino;
                c->cookie = ck;
                c->uid = r->idiag_uid;
                c->has_cookie = true;
            }
        }
    }
    close(fd);
}

static void enrich_sk_ptr_from_proc_net(const char *path, struct inode_sock_cand *cands, int cnt) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[512];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *saveptr = NULL;
        char *tok = strtok_r(line, " \t\r\n", &saveptr);
        int col = 0;
        uint64_t inode = 0;
        uint64_t sk_ptr = 0;
        while (tok) {
            if (col == 9) {
                inode = (uint64_t)strtoull(tok, NULL, 10);
            } else if (col == 11) {
                sk_ptr = (uint64_t)strtoull(tok, NULL, 16);
                break;
            }
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            col++;
        }

        if (inode == 0 || !is_valid_kernel_sk_ptr(sk_ptr))
            continue;

        for (int i = 0; i < cnt; i++) {
            if (cands[i].inode == inode) {
                cands[i].sk_ptr = sk_ptr;
                break;
            }
        }
    }
    fclose(fp);
}

static void enrich_from_proc_fds(struct inode_sock_cand *cands, int cnt) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *pde;
    while ((pde = readdir(proc_dir)) != NULL) {
        if (!isdigit((unsigned char)pde->d_name[0]))
            continue;
        int pid = atoi(pde->d_name);
        if (pid <= 0) continue;

        char fd_dir_path[64];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
        DIR *fdd = opendir(fd_dir_path);
        if (!fdd) continue;

        bool comm_loaded = false;
        char comm[16] = {0};

        struct dirent *fde;
        while ((fde = readdir(fdd)) != NULL) {
            if (fde->d_name[0] == '.') continue;
            char lpath[128], target[128];
            snprintf(lpath, sizeof(lpath), "/proc/%d/fd/%s", pid, fde->d_name);
            ssize_t r = readlink(lpath, target, sizeof(target) - 1);
            if (r <= 8) continue;
            target[r] = '\0';
            if (strncmp(target, "socket:[", 8) != 0)
                continue;
            uint64_t ino = (uint64_t)strtoull(target + 8, NULL, 10);
            if (ino == 0) continue;

            for (int i = 0; i < cnt; i++) {
                if (cands[i].inode == ino && !cands[i].has_owner) {
                    if (!comm_loaded) {
                        char cpath[64];
                        snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
                        FILE *cf = fopen(cpath, "r");
                        if (cf) {
                            if (fgets(comm, sizeof(comm), cf)) {
                                size_t cl = strlen(comm);
                                while (cl > 0 && (comm[cl - 1] == '\n' || comm[cl - 1] == '\r'))
                                    comm[--cl] = '\0';
                            }
                            fclose(cf);
                        }
                        comm_loaded = true;
                    }
                    cands[i].tgid = (uint32_t)pid;
                    memcpy(cands[i].comm, comm, sizeof(cands[i].comm));
                    cands[i].has_owner = true;
                }
            }
        }
        closedir(fdd);
    }
    closedir(proc_dir);
}

int proc_warmup_scan(struct dev_warm_sock *out, int max_entries) {
    if (!out || max_entries <= 0) return 0;

    int cap = max_entries < DEV_MAX_WARM_SOCKS ? max_entries : DEV_MAX_WARM_SOCKS;
    struct inode_sock_cand *cands = calloc((size_t)cap, sizeof(*cands));
    if (!cands) return 0;

    int cnt = 0;
    collect_sock_diag_family(AF_INET,  IPPROTO_TCP,    1, cands, &cnt, cap);
    collect_sock_diag_family(AF_INET6, IPPROTO_TCP,    2, cands, &cnt, cap);
    collect_sock_diag_family(AF_INET,  IPPROTO_UDP,    3, cands, &cnt, cap);
    collect_sock_diag_family(AF_INET6, IPPROTO_UDP,    4, cands, &cnt, cap);
    collect_sock_diag_family(AF_INET,  IPPROTO_ICMP,   5, cands, &cnt, cap);
    collect_sock_diag_family(AF_INET6, IPPROTO_ICMPV6, 6, cands, &cnt, cap);

    if (cnt == 0) {
        free(cands);
        return 0;
    }

    /* Enrich sk_ptr if kptr_restrict < 2 exposes kernel pointers */
    enrich_sk_ptr_from_proc_net("/proc/net/tcp",  cands, cnt);
    enrich_sk_ptr_from_proc_net("/proc/net/tcp6", cands, cnt);
    enrich_sk_ptr_from_proc_net("/proc/net/udp",  cands, cnt);
    enrich_sk_ptr_from_proc_net("/proc/net/udp6", cands, cnt);

    enrich_from_proc_fds(cands, cnt);

    int nout = 0;
    for (int i = 0; i < cnt && nout < max_entries; i++) {
        if (!cands[i].has_cookie || !cands[i].has_owner)
            continue;
        out[nout].sk_ptr = cands[i].sk_ptr;
        out[nout].cookie = cands[i].cookie;
        out[nout].tgid   = cands[i].tgid;
        out[nout].uid    = cands[i].uid;
        memcpy(out[nout].comm, cands[i].comm, 16);
        nout++;
    }

    free(cands);
    return nout;
}
