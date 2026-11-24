#define _GNU_SOURCE
#include "../include/pktpath_bpf.h"
#include "device_common.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
 * Minimal Zero-Dependency JSON Plugin Manifest Loader
 *
 * Schema:
 * {
 *   "schema_version": "1.0",
 *   "id": "my_plugin",
 *   "name": "My Custom Extension",
 *   "sock_fields": [
 *     { "struct": "sock", "field": "sk_mark", "size": 4, "role": "tag", "label": "mark_tag" },
 *     { "struct": "sock", "field": "custom_field", "size": 8, "role": "tgid_fallback", "label": "client_tgid" }
 *   ],
 *   "qdiscs": [
 *     { "id": "my_cls", "name": "My Classful Qdisc", "kind": "mycls", "mode": "classful", "enqueue_sym": "mycls_enqueue" },
 *     { "id": "my_leaf", "name": "My Leaf Qdisc", "kind": "myleaf", "mode": "leaf", "enqueue_sym": "myleaf_enqueue", "dequeue_sym": "myleaf_dequeue" }
 *   ]
 * }
 * ========================================================================== */

#define PLUGIN_MAX_FILE_BYTES (256U * 1024U)

struct js_cur {
    const char *p;
    const char *end;
};

static void js_skip_ws(struct js_cur *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\r' || *c->p == '\n'))
        c->p++;
}

static int js_expect(struct js_cur *c, char ch) {
    js_skip_ws(c);
    if (c->p < c->end && *c->p == ch) {
        c->p++;
        return 0;
    }
    return -1;
}

static int js_parse_string(struct js_cur *c, char *out, size_t cap) {
    js_skip_ws(c);
    if (c->p >= c->end || *c->p != '"')
        return -1;
    c->p++;
    size_t n = 0;
    while (c->p < c->end && *c->p != '"') {
        char ch = *c->p++;
        if (ch == '\\') {
            if (c->p >= c->end) return -1;
            char esc = *c->p++;
            switch (esc) {
            case '"':  ch = '"';  break;
            case '\\': ch = '\\'; break;
            case '/':  ch = '/';  break;
            case 'n':  ch = '\n'; break;
            case 'r':  ch = '\r'; break;
            case 't':  ch = '\t'; break;
            default:   ch = esc;  break;
            }
        }
        if (out && cap > 0 && n + 1 < cap)
            out[n++] = ch;
    }
    if (c->p >= c->end || *c->p != '"')
        return -1;
    c->p++;
    if (out && cap > 0)
        out[n] = '\0';
    return 0;
}

static int js_parse_uint(struct js_cur *c, uint64_t *out) {
    js_skip_ws(c);
    if (c->p >= c->end || !isdigit((unsigned char)*c->p))
        return -1;
    uint64_t v = 0;
    while (c->p < c->end && isdigit((unsigned char)*c->p)) {
        v = v * 10ULL + (uint64_t)(*c->p - '0');
        c->p++;
    }
    if (out) *out = v;
    return 0;
}

static int js_skip_value(struct js_cur *c);

static int js_skip_object(struct js_cur *c) {
    if (js_expect(c, '{') != 0) return -1;
    js_skip_ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return 0;
    }
    for (;;) {
        if (js_parse_string(c, NULL, 0) != 0) return -1;
        if (js_expect(c, ':') != 0) return -1;
        if (js_skip_value(c) != 0) return -1;
        js_skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        return js_expect(c, '}');
    }
}

static int js_skip_array(struct js_cur *c) {
    if (js_expect(c, '[') != 0) return -1;
    js_skip_ws(c);
    if (c->p < c->end && *c->p == ']') {
        c->p++;
        return 0;
    }
    for (;;) {
        if (js_skip_value(c) != 0) return -1;
        js_skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        return js_expect(c, ']');
    }
}

static int js_skip_value(struct js_cur *c) {
    js_skip_ws(c);
    if (c->p >= c->end) return -1;
    char ch = *c->p;
    if (ch == '"') return js_parse_string(c, NULL, 0);
    if (ch == '{') return js_skip_object(c);
    if (ch == '[') return js_skip_array(c);
    if (ch == 't' && (size_t)(c->end - c->p) >= 4 && memcmp(c->p, "true", 4) == 0) { c->p += 4; return 0; }
    if (ch == 'f' && (size_t)(c->end - c->p) >= 5 && memcmp(c->p, "false", 5) == 0) { c->p += 5; return 0; }
    if (ch == 'n' && (size_t)(c->end - c->p) >= 4 && memcmp(c->p, "null", 4) == 0) { c->p += 4; return 0; }
    if (ch == '-' || isdigit((unsigned char)ch)) {
        if (ch == '-') c->p++;
        while (c->p < c->end && (isdigit((unsigned char)*c->p) || *c->p == '.' ||
               *c->p == 'e' || *c->p == 'E' || *c->p == '+' || *c->p == '-')) {
            c->p++;
        }
        return 0;
    }
    return -1;
}

static int parse_sock_field_obj(struct js_cur *c, const char *plugin_id,
                                struct dev_plugin_registry *reg,
                                char *err_buf, size_t err_cap) {
    if (js_expect(c, '{') != 0) return -1;
    struct dev_plugin_sock_field sf;
    memset(&sf, 0, sizeof(sf));
    snprintf(sf.plugin_id, sizeof(sf.plugin_id), "%s", plugin_id);
    snprintf(sf.struct_name, sizeof(sf.struct_name), "sock");
    sf.size = 4;
    sf.role = PKT_SOCK_PLUG_TAG;

    js_skip_ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return 0;
    }
    for (;;) {
        char key[64] = "";
        if (js_parse_string(c, key, sizeof(key)) != 0) return -1;
        if (js_expect(c, ':') != 0) return -1;

        if (strcmp(key, "struct") == 0) {
            if (js_parse_string(c, sf.struct_name, sizeof(sf.struct_name)) != 0) return -1;
        } else if (strcmp(key, "field") == 0) {
            if (js_parse_string(c, sf.field_path, sizeof(sf.field_path)) != 0) return -1;
        } else if (strcmp(key, "label") == 0) {
            if (js_parse_string(c, sf.label, sizeof(sf.label)) != 0) return -1;
        } else if (strcmp(key, "role") == 0) {
            char role_str[32] = "";
            if (js_parse_string(c, role_str, sizeof(role_str)) != 0) return -1;
            if (strcmp(role_str, "tgid_fallback") == 0)
                sf.role = PKT_SOCK_PLUG_TGID_FALLBACK;
            else
                sf.role = PKT_SOCK_PLUG_TAG;
        } else if (strcmp(key, "size") == 0) {
            uint64_t sz = 0;
            if (js_parse_uint(c, &sz) != 0) return -1;
            if (sz == 1 || sz == 2 || sz == 4 || sz == 8)
                sf.size = (uint8_t)sz;
            else
                sf.size = 8;
        } else {
            if (js_skip_value(c) != 0) return -1;
        }
        js_skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        if (js_expect(c, '}') != 0) return -1;
        break;
    }

    if (!sf.field_path[0])
        return 0;
    if (!sf.label[0])
        snprintf(sf.label, sizeof(sf.label), "%s", sf.field_path);
    if (reg->num_sock_fields >= DEV_MAX_PLUGIN_SOCKS) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "plugin '%s': exceeded max %d sock_fields",
                     plugin_id, DEV_MAX_PLUGIN_SOCKS);
        return -1;
    }
    reg->sock_fields[reg->num_sock_fields++] = sf;
    return 0;
}

static int parse_qdisc_obj(struct js_cur *c, const char *plugin_id,
                           struct dev_plugin_registry *reg,
                           int *cls_slots_used, int *leaf_slots_used,
                           char *err_buf, size_t err_cap) {
    if (js_expect(c, '{') != 0) return -1;
    struct dev_plugin_qdisc qd;
    memset(&qd, 0, sizeof(qd));
    snprintf(qd.plugin_id, sizeof(qd.plugin_id), "%s", plugin_id);
    char qid[64] = "";

    js_skip_ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return 0;
    }
    for (;;) {
        char key[64] = "";
        if (js_parse_string(c, key, sizeof(key)) != 0) return -1;
        if (js_expect(c, ':') != 0) return -1;

        if (strcmp(key, "id") == 0) {
            if (js_parse_string(c, qid, sizeof(qid)) != 0) return -1;
        } else if (strcmp(key, "name") == 0) {
            if (js_parse_string(c, qd.name, sizeof(qd.name)) != 0) return -1;
        } else if (strcmp(key, "kind") == 0) {
            if (js_parse_string(c, qd.kind, sizeof(qd.kind)) != 0) return -1;
        } else if (strcmp(key, "mode") == 0) {
            char mode_str[32] = "";
            if (js_parse_string(c, mode_str, sizeof(mode_str)) != 0) return -1;
            qd.is_leaf = (strcmp(mode_str, "leaf") == 0);
        } else if (strcmp(key, "enqueue_sym") == 0) {
            if (js_parse_string(c, qd.enqueue_sym, sizeof(qd.enqueue_sym)) != 0) return -1;
        } else if (strcmp(key, "dequeue_sym") == 0) {
            if (js_parse_string(c, qd.dequeue_sym, sizeof(qd.dequeue_sym)) != 0) return -1;
        } else {
            if (js_skip_value(c) != 0) return -1;
        }
        js_skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        if (js_expect(c, '}') != 0) return -1;
        break;
    }

    if (!qd.kind[0] || !qd.enqueue_sym[0])
        return 0;
    if (qd.is_leaf && !qd.dequeue_sym[0]) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "plugin '%s' leaf qdisc '%s' requires dequeue_sym",
                     plugin_id, qd.kind);
        return -1;
    }
    if (!qid[0])
        snprintf(qid, sizeof(qid), "%s", qd.kind);
    snprintf(qd.adapter_id, sizeof(qd.adapter_id), "plugin_qdisc_%s", qid);
    if (!qd.name[0])
        snprintf(qd.name, sizeof(qd.name), "%s Qdisc Plugin", qd.kind);

    if (qd.is_leaf) {
        qd.slot_idx = (*leaf_slots_used)++;
    } else {
        qd.slot_idx = (*cls_slots_used)++;
    }
    if (reg->num_qdiscs >= DEV_MAX_PLUGIN_QDISCS) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "exceeded max %d qdisc plugins", DEV_MAX_PLUGIN_QDISCS);
        return -1;
    }
    reg->qdiscs[reg->num_qdiscs++] = qd;
    return 0;
}

static int load_one_plugin_file(const char *path, struct dev_plugin_registry *reg,
                                int *cls_slots_used, int *leaf_slots_used,
                                char *err_buf, size_t err_cap) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "open plugin '%s' failed: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long fsz = ftell(fp);
    if (fsz <= 0 || (size_t)fsz > PLUGIN_MAX_FILE_BYTES) {
        fclose(fp);
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "plugin '%s' has invalid size %ld", path, fsz);
        return -1;
    }
    rewind(fp);
    char *buf = malloc((size_t)fsz + 1U);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)fsz, fp);
    fclose(fp);
    buf[got] = '\0';

    /* Pass 1: find plugin id/name */
    char pid[64] = "";
    char pname[96] = "";
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(pid, sizeof(pid), "%s", base);
    char *dot = strrchr(pid, '.');
    if (dot) *dot = '\0';

    struct js_cur c = { buf, buf + got };
    if (js_expect(&c, '{') != 0) {
        free(buf);
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "plugin '%s': expected JSON object", path);
        return -1;
    }

    int start_sf = reg->num_sock_fields;
    int start_qd = reg->num_qdiscs;

    js_skip_ws(&c);
    if (c.p < c.end && *c.p != '}') {
        for (;;) {
            char key[64] = "";
            if (js_parse_string(&c, key, sizeof(key)) != 0) {
                free(buf);
                if (err_buf && err_cap)
                    snprintf(err_buf, err_cap, "plugin '%s': invalid JSON key", path);
                return -1;
            }
            if (js_expect(&c, ':') != 0) {
                free(buf);
                return -1;
            }
            if (strcmp(key, "id") == 0) {
                if (js_parse_string(&c, pid, sizeof(pid)) != 0) { free(buf); return -1; }
            } else if (strcmp(key, "name") == 0) {
                if (js_parse_string(&c, pname, sizeof(pname)) != 0) { free(buf); return -1; }
            } else if (strcmp(key, "sock_fields") == 0) {
                if (js_expect(&c, '[') != 0) { free(buf); return -1; }
                js_skip_ws(&c);
                if (c.p < c.end && *c.p == ']') {
                    c.p++;
                } else {
                    for (;;) {
                        if (parse_sock_field_obj(&c, pid, reg, err_buf, err_cap) != 0) {
                            free(buf);
                            return -1;
                        }
                        js_skip_ws(&c);
                        if (c.p < c.end && *c.p == ',') { c.p++; continue; }
                        if (js_expect(&c, ']') != 0) { free(buf); return -1; }
                        break;
                    }
                }
            } else if (strcmp(key, "qdiscs") == 0) {
                if (js_expect(&c, '[') != 0) { free(buf); return -1; }
                js_skip_ws(&c);
                if (c.p < c.end && *c.p == ']') {
                    c.p++;
                } else {
                    for (;;) {
                        if (parse_qdisc_obj(&c, pid, reg, cls_slots_used, leaf_slots_used,
                                            err_buf, err_cap) != 0) {
                            free(buf);
                            return -1;
                        }
                        js_skip_ws(&c);
                        if (c.p < c.end && *c.p == ',') { c.p++; continue; }
                        if (js_expect(&c, ']') != 0) { free(buf); return -1; }
                        break;
                    }
                }
            } else {
                if (js_skip_value(&c) != 0) { free(buf); return -1; }
            }
            js_skip_ws(&c);
            if (c.p < c.end && *c.p == ',') { c.p++; continue; }
            if (js_expect(&c, '}') != 0) { free(buf); return -1; }
            break;
        }
    }
    free(buf);

    if (!pname[0])
        snprintf(pname, sizeof(pname), "%s", pid);

    /* Stamp final parsed plugin id onto entries parsed before "id" key */
    for (int i = start_sf; i < reg->num_sock_fields; i++)
        snprintf(reg->sock_fields[i].plugin_id, sizeof(reg->sock_fields[i].plugin_id), "%s", pid);
    for (int i = start_qd; i < reg->num_qdiscs; i++)
        snprintf(reg->qdiscs[i].plugin_id, sizeof(reg->qdiscs[i].plugin_id), "%s", pid);

    if (reg->num_plugins < DEV_MAX_PLUGIN_PATHS) {
        snprintf(reg->plugin_ids[reg->num_plugins], sizeof(reg->plugin_ids[0]), "%s", pid);
        snprintf(reg->plugin_names[reg->num_plugins], sizeof(reg->plugin_names[0]), "%s", pname);
        reg->num_plugins++;
    }
    return 0;
}

static int cmp_str_ptr(const void *a, const void *b) {
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

int plugin_registry_load(const struct dev_cli_opts *opts, const struct btf_db *btf,
                         struct dev_plugin_registry *reg, char *err_buf, size_t err_cap) {
    memset(reg, 0, sizeof(*reg));
    if (!opts) return 0;

    char paths[DEV_MAX_PLUGIN_PATHS][512];
    int npaths = 0;

    for (int i = 0; i < opts->num_plugin_paths && npaths < DEV_MAX_PLUGIN_PATHS; i++) {
        if (opts->plugin_paths[i][0])
            snprintf(paths[npaths++], sizeof(paths[0]), "%s", opts->plugin_paths[i]);
    }

    if (opts->plugin_dir[0]) {
        DIR *dir = opendir(opts->plugin_dir);
        if (dir) {
            char *names[64];
            int nnames = 0;
            struct dirent *de;
            while ((de = readdir(dir)) != NULL && nnames < 64) {
                size_t l = strlen(de->d_name);
                if (l > 5 && strcmp(de->d_name + l - 5, ".json") == 0 && de->d_name[0] != '.') {
                    names[nnames++] = strdup(de->d_name);
                }
            }
            closedir(dir);
            if (nnames > 1)
                qsort(names, (size_t)nnames, sizeof(names[0]), cmp_str_ptr);
            for (int i = 0; i < nnames; i++) {
                if (npaths < DEV_MAX_PLUGIN_PATHS) {
                    snprintf(paths[npaths++], sizeof(paths[0]), "%s/%s",
                             opts->plugin_dir, names[i]);
                }
                free(names[i]);
            }
        }
    }

    int cls_slots_used = 0;
    int leaf_slots_used = 0;
    for (int i = 0; i < npaths; i++) {
        if (load_one_plugin_file(paths[i], reg, &cls_slots_used, &leaf_slots_used,
                                 err_buf, err_cap) != 0) {
            return -1;
        }
    }

    /* Resolve every sock_field against runtime /sys/kernel/btf/vmlinux */
    for (int i = 0; i < reg->num_sock_fields; i++) {
        struct dev_plugin_sock_field *sf = &reg->sock_fields[i];
        uint32_t off = 0;
        if (btf && btf_resolve_field(btf, sf->struct_name, sf->field_path, &off) == 0 && off > 0) {
            sf->resolved_offset = off;
            sf->resolved = true;
        } else {
            sf->resolved_offset = 0;
            sf->resolved = false;
            snprintf(sf->error, sizeof(sf->error), "BTF field %s.%s absent on this kernel",
                     sf->struct_name, sf->field_path);
        }
    }
    return 0;
}
