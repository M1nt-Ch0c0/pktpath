#define _GNU_SOURCE
#include "device_common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ==========================================================================
 * Pure-C Binary BTF Parser (/sys/kernel/btf/vmlinux)
 * Supports BTF v1 kinds 1..19, typedef/const/volatile/restrict/type_tag
 * chasing, anonymous nested structs/unions, and multi-hop dotted paths.
 * ========================================================================== */

#define BTF_MAGIC_LE 0xEB9FU
#define BTF_MAX_FILE_BYTES (64U * 1024U * 1024U)

struct btf_raw_hdr {
    uint16_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};

struct btf_raw_type {
    uint32_t name_off;
    uint32_t info;
    uint32_t size_or_type;
};

struct btf_raw_member {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
};

struct btf_type_idx {
    uint32_t name_off;
    uint32_t info;
    uint32_t size_or_type;
    uint32_t members_byte_off; /* offset into db->data for STRUCT/UNION members */
};

struct btf_db {
    uint8_t             *data;
    size_t               data_len;
    const char          *strs;
    uint32_t             str_len;
    uint32_t             nr_types; /* 1-based: types[1 .. nr_types] */
    struct btf_type_idx *types;
};

static inline uint32_t btf_info_vlen(uint32_t info) {
    return info & 0xFFFFU;
}

static inline uint32_t btf_info_kind(uint32_t info) {
    return (info >> 24) & 0x1FU;
}

static inline uint32_t btf_info_kflag(uint32_t info) {
    return (info >> 31) & 0x1U;
}

static const char *btf_str(const struct btf_db *db, uint32_t off) {
    if (off >= db->str_len) return "";
    /* Ensure NUL termination within string section */
    if (!memchr(db->strs + off, '\0', db->str_len - off)) return "";
    return db->strs + off;
}

static int btf_kind_extra_bytes(uint32_t kind, uint32_t vlen, size_t *out) {
    switch (kind) {
    case 1:  /* BTF_KIND_INT */
    case 14: /* BTF_KIND_VAR */
    case 17: /* BTF_KIND_DECL_TAG */
        *out = 4;
        return 0;
    case 2:  /* BTF_KIND_PTR */
    case 7:  /* BTF_KIND_FWD */
    case 8:  /* BTF_KIND_TYPEDEF */
    case 9:  /* BTF_KIND_VOLATILE */
    case 10: /* BTF_KIND_CONST */
    case 11: /* BTF_KIND_RESTRICT */
    case 12: /* BTF_KIND_FUNC */
    case 16: /* BTF_KIND_FLOAT */
    case 18: /* BTF_KIND_TYPE_TAG */
        *out = 0;
        return 0;
    case 3:  /* BTF_KIND_ARRAY */
        *out = 12;
        return 0;
    case 4:  /* BTF_KIND_STRUCT */
    case 5:  /* BTF_KIND_UNION */
    case 15: /* BTF_KIND_DATASEC */
    case 19: /* BTF_KIND_ENUM64 */
        *out = (size_t)vlen * 12U;
        return 0;
    case 6:  /* BTF_KIND_ENUM */
    case 13: /* BTF_KIND_FUNC_PROTO */
        *out = (size_t)vlen * 8U;
        return 0;
    default:
        return -1;
    }
}

struct btf_db *btf_db_load(const char *path, char *err_buf, size_t err_cap) {
    const char *p = path ? path : "/sys/kernel/btf/vmlinux";
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "open(%s) failed: %s", p, strerror(errno));
        return NULL;
    }

    size_t cap = 1024U * 1024U;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        close(fd);
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory reading BTF");
        return NULL;
    }

    for (;;) {
        if (len == cap) {
            if (cap >= BTF_MAX_FILE_BYTES) {
                free(buf);
                close(fd);
                if (err_buf && err_cap) snprintf(err_buf, err_cap, "BTF file exceeds 64 MiB limit");
                return NULL;
            }
            size_t ncap = cap * 2U;
            if (ncap > BTF_MAX_FILE_BYTES) ncap = BTF_MAX_FILE_BYTES;
            uint8_t *nbuf = realloc(buf, ncap);
            if (!nbuf) {
                free(buf);
                close(fd);
                if (err_buf && err_cap) snprintf(err_buf, err_cap, "realloc failed reading BTF");
                return NULL;
            }
            buf = nbuf;
            cap = ncap;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (err_buf && err_cap)
                snprintf(err_buf, err_cap, "read(%s) failed: %s", p, strerror(errno));
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);

    if (len < sizeof(struct btf_raw_hdr)) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "BTF header truncated (%zu B)", len);
        free(buf);
        return NULL;
    }

    struct btf_raw_hdr hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.magic != BTF_MAGIC_LE || hdr.version != 1 || hdr.hdr_len < sizeof(hdr)) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "invalid BTF header (magic=0x%x ver=%u)", hdr.magic, hdr.version);
        free(buf);
        return NULL;
    }

    uint64_t type_start = (uint64_t)hdr.hdr_len + hdr.type_off;
    uint64_t type_end   = type_start + hdr.type_len;
    uint64_t str_start  = (uint64_t)hdr.hdr_len + hdr.str_off;
    uint64_t str_end    = str_start + hdr.str_len;
    if (type_end > len || str_end > len) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "BTF section offsets exceed file size");
        free(buf);
        return NULL;
    }

    /* Pass 1: count types and verify integrity */
    uint32_t count = 0;
    size_t off = (size_t)type_start;
    while (off < (size_t)type_end) {
        if ((size_t)type_end - off < sizeof(struct btf_raw_type)) {
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "truncated btf_type at %zu", off);
            free(buf);
            return NULL;
        }
        struct btf_raw_type rt;
        memcpy(&rt, buf + off, sizeof(rt));
        off += sizeof(rt);

        uint32_t kind = btf_info_kind(rt.info);
        uint32_t vlen = btf_info_vlen(rt.info);
        size_t extra = 0;
        if (btf_kind_extra_bytes(kind, vlen, &extra) != 0 || extra > (size_t)type_end - off) {
            if (err_buf && err_cap)
                snprintf(err_buf, err_cap, "unsupported/corrupt BTF kind=%u at type #%u", kind, count + 1);
            free(buf);
            return NULL;
        }
        off += extra;
        count++;
    }

    struct btf_db *db = calloc(1, sizeof(*db));
    if (!db) {
        free(buf);
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory allocating btf_db");
        return NULL;
    }
    db->types = calloc((size_t)count + 1U, sizeof(struct btf_type_idx));
    if (!db->types) {
        free(db);
        free(buf);
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory allocating btf types");
        return NULL;
    }

    db->data = buf;
    db->data_len = len;
    db->strs = (const char *)(buf + str_start);
    db->str_len = hdr.str_len;
    db->nr_types = count;

    /* Pass 2: populate index */
    off = (size_t)type_start;
    for (uint32_t id = 1; id <= count; id++) {
        struct btf_raw_type rt;
        memcpy(&rt, buf + off, sizeof(rt));
        off += sizeof(rt);

        uint32_t kind = btf_info_kind(rt.info);
        uint32_t vlen = btf_info_vlen(rt.info);
        size_t extra = 0;
        btf_kind_extra_bytes(kind, vlen, &extra);

        db->types[id].name_off = rt.name_off;
        db->types[id].info = rt.info;
        db->types[id].size_or_type = rt.size_or_type;
        db->types[id].members_byte_off = (kind == 4 || kind == 5 || kind == 6 || kind == 19) ? (uint32_t)off : 0;
        off += extra;
    }

    return db;
}

void btf_db_free(struct btf_db *db) {
    if (!db) return;
    free(db->types);
    free(db->data);
    free(db);
}

static uint32_t btf_chase_modifiers(const struct btf_db *db, uint32_t type_id) {
    for (int depth = 0; depth < 16; depth++) {
        if (type_id == 0 || type_id > db->nr_types) return 0;
        uint32_t kind = btf_info_kind(db->types[type_id].info);
        /* TYPEDEF(8), VOLATILE(9), CONST(10), RESTRICT(11), TYPE_TAG(18) */
        if (kind == 8 || kind == 9 || kind == 10 || kind == 11 || kind == 18) {
            type_id = db->types[type_id].size_or_type;
            continue;
        }
        return type_id;
    }
    return 0;
}

static int btf_find_member(const struct btf_db *db, uint32_t type_id, const char *member_name,
                           int depth, uint32_t *out_type_id, uint32_t *out_bit_off) {
    if (depth > 16) return -1;
    type_id = btf_chase_modifiers(db, type_id);
    if (type_id == 0 || type_id > db->nr_types) return -1;

    const struct btf_type_idx *ti = &db->types[type_id];
    uint32_t kind = btf_info_kind(ti->info);
    if (kind != 4 && kind != 5) return -1;

    uint32_t vlen = btf_info_vlen(ti->info);
    uint32_t kflag = btf_info_kflag(ti->info);
    size_t mbase = ti->members_byte_off;

    for (uint32_t j = 0; j < vlen; j++) {
        struct btf_raw_member rm;
        memcpy(&rm, db->data + mbase + (size_t)j * sizeof(rm), sizeof(rm));
        const char *mname = btf_str(db, rm.name_off);
        uint32_t bit_off = kflag ? (rm.offset & 0xFFFFFFU) : rm.offset;

        if (mname[0] != '\0') {
            if (strcmp(mname, member_name) == 0) {
                *out_type_id = rm.type;
                *out_bit_off = bit_off;
                return 0;
            }
        } else {
            /* Anonymous nested struct or union: recurse transparently */
            uint32_t inner_type = 0;
            uint32_t inner_bit = 0;
            if (btf_find_member(db, rm.type, member_name, depth + 1,
                                &inner_type, &inner_bit) == 0) {
                *out_type_id = inner_type;
                *out_bit_off = bit_off + inner_bit;
                return 0;
            }
        }
    }
    return -1;
}

int btf_resolve_field(const struct btf_db *db, const char *struct_name,
                      const char *field_path, uint32_t *byte_off_out) {
    if (!db || !struct_name || !field_path || !byte_off_out) return -1;

    for (uint32_t id = 1; id <= db->nr_types; id++) {
        uint32_t kind = btf_info_kind(db->types[id].info);
        if (kind != 4 && kind != 5) continue;
        if (btf_info_vlen(db->types[id].info) == 0) continue;
        const char *tname = btf_str(db, db->types[id].name_off);
        if (strcmp(tname, struct_name) != 0) continue;

        char path_copy[128];
        snprintf(path_copy, sizeof(path_copy), "%s", field_path);

        uint32_t cur_type = id;
        uint32_t total_bits = 0;
        bool ok = true;
        char *saveptr = NULL;
        for (char *tok = strtok_r(path_copy, ".", &saveptr);
             tok != NULL;
             tok = strtok_r(NULL, ".", &saveptr)) {
            uint32_t next_type = 0;
            uint32_t bit_off = 0;
            if (btf_find_member(db, cur_type, tok, 0, &next_type, &bit_off) != 0) {
                ok = false;
                break;
            }
            total_bits += bit_off;
            cur_type = next_type;
        }

        if (ok && (total_bits % 8U) == 0U) {
            *byte_off_out = total_bits / 8U;
            return 0;
        }
    }
    return -1;
}

static int btf_resolve_bitfield_container_byte(const struct btf_db *db, const char *struct_name,
                                               const char *field_path, uint32_t *byte_off_out) {
    if (!db || !struct_name || !field_path || !byte_off_out) return -1;
    for (uint32_t id = 1; id <= db->nr_types; id++) {
        uint32_t kind = btf_info_kind(db->types[id].info);
        if (kind != 4 && kind != 5) continue;
        if (btf_info_vlen(db->types[id].info) == 0) continue;
        if (strcmp(btf_str(db, db->types[id].name_off), struct_name) != 0) continue;

        char path_copy[128];
        snprintf(path_copy, sizeof(path_copy), "%s", field_path);
        uint32_t cur_type = id, total_bits = 0;
        bool ok = true;
        char *saveptr = NULL;
        for (char *tok = strtok_r(path_copy, ".", &saveptr);
             tok != NULL;
             tok = strtok_r(NULL, ".", &saveptr)) {
            uint32_t next_type = 0, bit_off = 0;
            if (btf_find_member(db, cur_type, tok, 0, &next_type, &bit_off) != 0) {
                ok = false;
                break;
            }
            total_bits += bit_off;
            cur_type = next_type;
        }
        if (ok) {
            *byte_off_out = total_bits / 8U;
            return 0;
        }
    }
    return -1;
}

int btf_find_func_id(const struct btf_db *db, const char *func_name) {
    if (!db || !func_name) return -1;
    for (uint32_t id = 1; id <= db->nr_types; id++) {
        if (btf_info_kind(db->types[id].info) != 12) continue; /* BTF_KIND_FUNC */
        if (strcmp(btf_str(db, db->types[id].name_off), func_name) == 0)
            return (int)id;
    }
    return -1;
}

static int btf_find_struct_size(const struct btf_db *db, const char *struct_name,
                                uint32_t *size_out) {
    if (!db || !struct_name || !size_out) return -1;
    for (uint32_t id = 1; id <= db->nr_types; id++) {
        if (btf_info_kind(db->types[id].info) != 4) continue;
        if (btf_info_vlen(db->types[id].info) == 0) continue;
        if (strcmp(btf_str(db, db->types[id].name_off), struct_name) == 0) {
            *size_out = db->types[id].size_or_type;
            return 0;
        }
    }
    return -1;
}

static void parse_tracefs_kfree_reason_offset(uint32_t *out) {
    if (*out != 0) return;
    char path[256];
    snprintf(path, sizeof(path), "%s/events/skb/kfree_skb/format", tracefs_root());
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "reason;")) continue;
        const char *off_p = strstr(line, "offset:");
        if (off_p) {
            unsigned long v = strtoul(off_p + 7, NULL, 10);
            if (v >= 16 && v <= 128) {
                *out = (uint32_t)v;
                break;
            }
        }
    }
    fclose(fp);
}

static int req_field(const struct btf_db *db, const char *st, const char *path,
                     uint32_t *dst, char *err, size_t err_cap) {
    if (btf_resolve_field(db, st, path, dst) != 0) {
        if (err && err_cap)
            snprintf(err, err_cap, "missing required BTF field %s.%s", st, path);
        return -1;
    }
    return 0;
}

int btf_resolve_all_offsets(const struct btf_db *db, struct dev_btf_resolved *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!db) {
        snprintf(out->error, sizeof(out->error), "BTF database is NULL");
        return -1;
    }

    char *e = out->error;
    size_t ec = sizeof(out->error);

    /* 1. struct sk_buff required fields */
    if (req_field(db, "sk_buff", "dev", &out->skb_dev, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "sk", &out->skb_sk, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "len", &out->skb_len, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "data_len", &out->skb_data_len, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "head", &out->skb_head, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "data", &out->skb_data, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "network_header", &out->skb_network_header, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "transport_header", &out->skb_transport_header, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "mac_header", &out->skb_mac_header, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "protocol", &out->skb_protocol, e, ec) != 0) return -1;
    if (btf_resolve_field(db, "sk_buff", "__pkt_type_offset", &out->skb_pkt_type) != 0 &&
        btf_resolve_bitfield_container_byte(db, "sk_buff", "pkt_type", &out->skb_pkt_type) != 0) {
        out->skb_pkt_type = 128U;
    }
    if (req_field(db, "sk_buff", "hash", &out->skb_hash, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "mark", &out->skb_mark, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "priority", &out->skb_priority, e, ec) != 0) return -1;
    if (req_field(db, "sk_buff", "cb", &out->skb_cb, e, ec) != 0) return -1;
    (void)btf_resolve_field(db, "sk_buff", "tstamp", &out->skb_tstamp);
    (void)btf_resolve_field(db, "sk_buff", "queue_mapping", &out->skb_queue_mapping);

    /* 2. struct net_device & struct net */
    if (req_field(db, "net_device", "ifindex", &out->dev_ifindex, e, ec) != 0) return -1;
    if (btf_resolve_field(db, "net_device", "nd_net.net", &out->dev_nd_net) != 0 &&
        req_field(db, "net_device", "nd_net", &out->dev_nd_net, e, ec) != 0) {
        return -1;
    }
    if (req_field(db, "net", "ns.inum", &out->net_ns_inum, e, ec) != 0) return -1;

    /* 3. struct sock & struct socket */
    if (btf_resolve_field(db, "sock", "__sk_common.skc_state", &out->sk_state) != 0 &&
        req_field(db, "sock_common", "skc_state", &out->sk_state, e, ec) != 0) {
        return -1;
    }
    if (btf_resolve_field(db, "sock", "__sk_common.skc_cookie.counter", &out->sk_cookie) != 0 &&
        btf_resolve_field(db, "sock", "__sk_common.skc_cookie", &out->sk_cookie) != 0 &&
        req_field(db, "sock_common", "skc_cookie", &out->sk_cookie, e, ec) != 0) {
        return -1;
    }
    if (btf_resolve_field(db, "sock", "sk_uid.val", &out->sk_uid) != 0 &&
        req_field(db, "sock", "sk_uid", &out->sk_uid, e, ec) != 0) {
        return -1;
    }
    if (req_field(db, "socket", "sk", &out->socket_sk, e, ec) != 0) return -1;

    /* 4. struct Qdisc & optional struct netdev_queue */
    if (req_field(db, "Qdisc", "handle", &out->qdisc_handle, e, ec) != 0) return -1;
    if (req_field(db, "Qdisc", "parent", &out->qdisc_parent, e, ec) != 0) return -1;
    (void)btf_resolve_field(db, "netdev_queue", "dev", &out->netdev_queue_dev);
    (void)btf_resolve_field(db, "netdev_queue", "state", &out->netdev_queue_state);

    /* 5. struct task_struct preempt_count (arm64 thread_info.preempt.count) */
    if (btf_resolve_field(db, "task_struct", "thread_info.preempt.count", &out->task_preempt_count) != 0 &&
        btf_resolve_field(db, "task_struct", "thread_info.preempt_count", &out->task_preempt_count) != 0 &&
        req_field(db, "thread_info", "preempt.count", &out->task_preempt_count, e, ec) != 0) {
        return -1;
    }

    /* 6. Optional tracepoint, netdev_queue & tc classify helpers */
    (void)btf_resolve_field(db, "trace_event_raw_kfree_skb", "reason", &out->tp_kfree_skb_reason);
    parse_tracefs_kfree_reason_offset(&out->tp_kfree_skb_reason);
    (void)btf_resolve_field(db, "net_device", "_tx", &out->dev_tx_queues);
    (void)btf_find_struct_size(db, "netdev_queue", &out->netdev_queue_sz);
    if (btf_resolve_field(db, "tcf_result", "classid", &out->tcf_res_classid) != 0)
        out->tcf_res_classid = 8U;

    out->loaded = true;
    return 0;
}

/* ==========================================================================
 * Wave 3: Export kernel enum (BTF_KIND_ENUM / BTF_KIND_ENUM64) for e.g.
 * `enum skb_drop_reason` from /sys/kernel/btf/vmlinux.
 * ========================================================================== */

struct btf_raw_enum {
    uint32_t name_off;
    int32_t  val;
};

struct btf_raw_enum64 {
    uint32_t name_off;
    uint32_t val_lo32;
    uint32_t val_hi32;
};

int btf_export_enum(const struct btf_db *db, const char *enum_name,
                    struct btf_enum_entry *out, size_t max_entries, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!db || !enum_name || !enum_name[0] || !out || max_entries == 0)
        return -1;

    for (uint32_t id = 1; id <= db->nr_types; id++) {
        const struct btf_type_idx *t = &db->types[id];
        uint32_t kind = btf_info_kind(t->info);
        if (kind != 6U && kind != 19U) /* BTF_KIND_ENUM or BTF_KIND_ENUM64 */
            continue;
        const char *name = btf_str(db, t->name_off);
        if (strcmp(name, enum_name) != 0)
            continue;

        uint32_t vlen = btf_info_vlen(t->info);
        uint32_t kflag = btf_info_kflag(t->info);
        size_t off = (size_t)t->members_byte_off;
        size_t elem_sz = (kind == 19U) ? sizeof(struct btf_raw_enum64) : sizeof(struct btf_raw_enum);
        if (off > db->data_len || (size_t)vlen * elem_sz > db->data_len - off)
            return -1;

        size_t cnt = 0;
        for (uint32_t i = 0; i < vlen && cnt < max_entries; i++) {
            const uint8_t *p = db->data + off + (size_t)i * elem_sz;
            uint32_t e_name_off = 0;
            int64_t val = 0;
            if (kind == 6U) {
                struct btf_raw_enum e;
                memcpy(&e, p, sizeof(e));
                e_name_off = e.name_off;
                val = kflag ? (int64_t)e.val : (int64_t)(uint32_t)e.val;
            } else {
                struct btf_raw_enum64 e64;
                memcpy(&e64, p, sizeof(e64));
                e_name_off = e64.name_off;
                uint64_t u64 = ((uint64_t)e64.val_hi32 << 32) | (uint64_t)e64.val_lo32;
                val = (int64_t)u64;
            }
            const char *ename = btf_str(db, e_name_off);
            if (!ename || !ename[0])
                continue;
            out[cnt].value = val;
            snprintf(out[cnt].name, sizeof(out[cnt].name), "%s", ename);
            cnt++;
        }
        if (out_count) *out_count = cnt;
        return 0;
    }
    return -1;
}
