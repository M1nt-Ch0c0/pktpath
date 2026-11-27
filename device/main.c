#define _GNU_SOURCE
#include "device_common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(FILE *fp) {
    fprintf(fp,
        "Usage:\n"
        "  pktpath inspect --dev <ifname> --scope <tc-egress|ip-tx|sock-tx|rx-sock|fwd>\n"
        "    [--plugin <file.json>]... [--plugin-dir <dir>] [--json]\n"
        "  pktpath record --mode <oneshot|daemon> --dev <ifname> --scope <...>\n"
        "    [--proto tcp|udp|icmp|icmpv6] [--src-ip CIDR] [--dst-ip CIDR]\n"
        "    [--src-port N] [--dst-port N] [--mark VAL[/MASK]] [--uid U] [--tgid P]\n"
        "    [--sample 1/N] [--sample-by pkt|flow] [--duration Ns]\n"
        "    [--mem-budget MB] [--disk-budget MB]\n"
        "    [--trigger 'sojourn_us>X,drop_burst>Y'] [--pre-window Ns] [--post-window Ns]\n"
        "    [--profile sendmsg] [--plugin <file.json>]... [--plugin-dir <dir>]\n"
        "    [--probe-groups <csv>] [--preset <egress|drop-pwru|full-path|tcp-diag>] [--preset-label <name>]\n"
        "    [--capture-hdr N] [--allow-partial] --out <dir>\n");
}

static int parse_scope(const char *s, enum dev_scope *out) {
    if (strcmp(s, "tc-egress") == 0) { *out = SCOPE_TC_EGRESS; return 0; }
    if (strcmp(s, "ip-tx") == 0)     { *out = SCOPE_IP_TX;     return 0; }
    if (strcmp(s, "sock-tx") == 0)   { *out = SCOPE_SOCK_TX;   return 0; }
    if (strcmp(s, "rx-sock") == 0)   { *out = SCOPE_RX_SOCK;   return 0; }
    if (strcmp(s, "fwd") == 0)       { *out = SCOPE_FWD;       return 0; }
    return -1;
}

/* CLI numerics are unsigned ASCII, with complete suffix consumption by the
 * caller. strtoull alone accepts signs, whitespace and saturated overflow. */
static int parse_unsigned_prefix(const char *s, int base, uint64_t *out, const char **tail) {
    if (!s || s[0] < '0' || s[0] > '9') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, base);
    if (errno != 0 || end == s || v > UINT64_MAX) return -1;
    *out = (uint64_t)v;
    *tail = end;
    return 0;
}

static int parse_unsigned(const char *s, int base, uint64_t limit, uint64_t *out) {
    const char *end;
    uint64_t v;
    if (parse_unsigned_prefix(s, base, &v, &end) != 0 || *end != '\0' || v > limit) return -1;
    *out = v;
    return 0;
}

static int parse_u32(const char *s, int base, uint32_t *out) {
    uint64_t v;
    if (parse_unsigned(s, base, UINT32_MAX, &v) != 0) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int parse_seconds(const char *s, uint32_t *out) {
    const char *end;
    uint64_t v, seconds;
    if (parse_unsigned_prefix(s, 10, &v, &end) != 0) return -1;
    if (*end == '\0' || strcmp(end, "s") == 0 || strcmp(end, "sec") == 0) {
        seconds = v;
    } else if (strcmp(end, "m") == 0) {
        if (v > UINT32_MAX / 60U) return -1;
        seconds = v * 60U;
    } else if (strcmp(end, "ms") == 0) {
        /* Preserve ceil-to-seconds without the overflowing v + 999. */
        seconds = v / 1000U + (v % 1000U != 0);
    } else {
        return -1;
    }
    if (seconds > UINT32_MAX) return -1;
    *out = (uint32_t)seconds; /* explicit 0 retains its existing meaning */
    return 0;
}

static int parse_budget_bytes(const char *s, uint64_t *out) {
    const char *end;
    uint64_t v, scale;
    if (parse_unsigned_prefix(s, 10, &v, &end) != 0) return -1;
    while (*end == ' ') end++; /* keep existing spaces before budget units */
    if (*end == '\0' || strcasecmp(end, "m") == 0 || strcasecmp(end, "mb") == 0 ||
        strcasecmp(end, "mib") == 0) {
        scale = 1024ULL * 1024ULL;
    } else if (strcasecmp(end, "k") == 0 || strcasecmp(end, "kb") == 0 || strcasecmp(end, "kib") == 0) {
        scale = 1024ULL;
    } else if (strcasecmp(end, "g") == 0 || strcasecmp(end, "gb") == 0 || strcasecmp(end, "gib") == 0) {
        scale = 1024ULL * 1024ULL * 1024ULL;
    } else if (strcasecmp(end, "b") == 0) {
        scale = 1;
    } else {
        return -1;
    }
    if (v > UINT64_MAX / scale) return -1;
    *out = v * scale;
    return 0;
}

static int parse_cidr(const char *s, uint8_t *ip_ver_io, uint32_t *ip4_out,
                      uint32_t *mask4_out, uint8_t ip6_out[16], uint8_t *pfx6_out) {
    char copy[128];
    if (!s || strlen(s) >= sizeof(copy)) return -1;
    snprintf(copy, sizeof(copy), "%s", s);
    char *slash = strchr(copy, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        uint64_t p;
        if (parse_unsigned(slash + 1, 10, 128, &p) != 0) return -1;
        prefix = (int)p;
    }

    struct in_addr a4;
    if (inet_pton(AF_INET, copy, &a4) == 1) {
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return -1;
        if (*ip_ver_io != 0 && *ip_ver_io != 4) return -1;
        *ip_ver_io = 4;
        uint32_t hmask = (prefix == 0) ? 0U : (0xFFFFFFFFU << (32 - prefix));
        *mask4_out = htonl(hmask);
        *ip4_out = a4.s_addr & (*mask4_out);
        return 0;
    }

    struct in6_addr a6;
    if (inet_pton(AF_INET6, copy, &a6) == 1) {
        if (prefix < 0) prefix = 128;
        if (prefix > 128) return -1;
        if (*ip_ver_io != 0 && *ip_ver_io != 6) return -1;
        *ip_ver_io = 6;
        memcpy(ip6_out, a6.s6_addr, 16);
        *pfx6_out = (uint8_t)prefix;
        return 0;
    }
    return -1;
}

static int parse_sample(const char *s, uint32_t *stride_out, char *norm_out, size_t norm_cap) {
    uint64_t n;
    bool fraction = strncmp(s, "1/", 2) == 0;
    if (parse_unsigned(fraction ? s + 2 : s, 10,
                       fraction ? 1000000U : UINT32_MAX, &n) != 0 || (fraction && n == 0)) return -1;
    *stride_out = (uint32_t)n;
    if (n == 0) snprintf(norm_out, norm_cap, "0");
    else snprintf(norm_out, norm_cap, "1/%llu", (unsigned long long)n);
    return 0;
}

static int parse_trigger(const char *s, struct dev_cli_opts *opts) {
    char copy[256];
    if (!s || strlen(s) >= sizeof(copy)) return -1;
    snprintf(copy, sizeof(copy), "%s", s);
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ",", &saveptr);
         tok != NULL;
         tok = strtok_r(NULL, ",", &saveptr)) {
        while (*tok == ' ') tok++;
        if (strncmp(tok, "sojourn_us>", 11) == 0) {
            if (parse_unsigned(tok + 11, 10, UINT64_MAX, &opts->trigger_sojourn_us) != 0) return -1;
        } else if (strncmp(tok, "drop_burst>", 11) == 0) {
            if (parse_u32(tok + 11, 10, &opts->trigger_drop_burst) != 0) return -1;
        } else if (*tok != '\0') {
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(stderr);
        return 2;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }

    struct dev_cli_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.mode = MODE_ONESHOT;
    opts.scope = SCOPE_TC_EGRESS;
    opts.uid = 0xFFFFFFFFU;
    opts.sample_stride = 1;
    snprintf(opts.sample_rate_str, sizeof(opts.sample_rate_str), "1/1");
    opts.duration_sec = 10;
    opts.mem_budget_bytes = 32ULL * 1024ULL * 1024ULL;
    opts.disk_budget_bytes = 128ULL * 1024ULL * 1024ULL;
    opts.pre_window_sec = 5;
    opts.post_window_sec = 5;

    bool duration_set = false;

    if (strcmp(argv[1], "inspect") == 0) {
        opts.is_record = false;
    } else if (strcmp(argv[1], "record") == 0) {
        opts.is_record = true;
    } else {
        fprintf(stderr, "error: unknown subcommand '%s' (expected 'inspect' or 'record')\n", argv[1]);
        print_usage(stderr);
        return 2;
    }

    for (int i = 2; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(stdout);
            return 0;
        } else if (strcmp(arg, "--json") == 0) {
            opts.json_output = true;
        } else if (strcmp(arg, "--allow-partial") == 0) {
            opts.allow_partial = true;
        } else if (strcmp(arg, "--dev") == 0 && i + 1 < argc) {
            snprintf(opts.dev_name, sizeof(opts.dev_name), "%s", argv[++i]);
        } else if (strcmp(arg, "--scope") == 0 && i + 1 < argc) {
            if (parse_scope(argv[++i], &opts.scope) != 0) {
                fprintf(stderr, "error: invalid --scope '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--mode") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "oneshot") == 0) opts.mode = MODE_ONESHOT;
            else if (strcmp(m, "daemon") == 0) opts.mode = MODE_DAEMON;
            else {
                fprintf(stderr, "error: invalid --mode '%s' (expected oneshot|daemon)\n", m);
                return 2;
            }
        } else if (strcmp(arg, "--proto") == 0 && i + 1 < argc) {
            const char *p = argv[++i];
            if (strcmp(p, "tcp") == 0) opts.filter_proto = IPPROTO_TCP;
            else if (strcmp(p, "udp") == 0) opts.filter_proto = IPPROTO_UDP;
            else if (strcmp(p, "icmp") == 0) opts.filter_proto = IPPROTO_ICMP;
            else if (strcmp(p, "icmpv6") == 0 || strcmp(p, "icmp6") == 0) opts.filter_proto = IPPROTO_ICMPV6;
            else {
                fprintf(stderr, "error: invalid --proto '%s'\n", p);
                return 2;
            }
        } else if (strcmp(arg, "--src-ip") == 0 && i + 1 < argc) {
            if (parse_cidr(argv[++i], &opts.filter_ip_ver, &opts.src_ip4,
                           &opts.src_mask4, opts.src_ip6, &opts.src_prefix6) != 0) {
                fprintf(stderr, "error: invalid --src-ip '%s'\n", argv[i]);
                return 2;
            }
            opts.has_src_ip = true;
        } else if (strcmp(arg, "--dst-ip") == 0 && i + 1 < argc) {
            if (parse_cidr(argv[++i], &opts.filter_ip_ver, &opts.dst_ip4,
                           &opts.dst_mask4, opts.dst_ip6, &opts.dst_prefix6) != 0) {
                fprintf(stderr, "error: invalid --dst-ip '%s'\n", argv[i]);
                return 2;
            }
            opts.has_dst_ip = true;
        } else if (strcmp(arg, "--src-port") == 0 && i + 1 < argc) {
            uint64_t p;
            if (parse_unsigned(argv[++i], 10, 65535U, &p) != 0 || p == 0) {
                fprintf(stderr, "error: invalid --src-port '%s'\n", argv[i]);
                return 2;
            }
            opts.src_port = (uint16_t)p;
        } else if (strcmp(arg, "--dst-port") == 0 && i + 1 < argc) {
            uint64_t p;
            if (parse_unsigned(argv[++i], 10, 65535U, &p) != 0 || p == 0) {
                fprintf(stderr, "error: invalid --dst-port '%s'\n", argv[i]);
                return 2;
            }
            opts.dst_port = (uint16_t)p;
        } else if (strcmp(arg, "--mark") == 0 && i + 1 < argc) {
            const char *ms = argv[++i];
            char copy[64];
            if (strlen(ms) >= sizeof(copy)) {
                fprintf(stderr, "error: invalid --mark '%s'\n", ms);
                return 2;
            }
            snprintf(copy, sizeof(copy), "%s", ms);
            char *sl = strchr(copy, '/');
            if (sl) *sl++ = '\0';
            if (parse_u32(copy, 0, &opts.mark_val) != 0 ||
                (sl && parse_u32(sl, 0, &opts.mark_mask) != 0)) {
                fprintf(stderr, "error: invalid --mark '%s'\n", ms);
                return 2;
            }
            if (!sl) opts.mark_mask = UINT32_MAX;
            opts.has_mark = true;
        } else if (strcmp(arg, "--uid") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 10, &opts.uid) != 0) {
                fprintf(stderr, "error: invalid --uid '%s'\n", argv[i]);
                return 2;
            }
            opts.has_uid = true;
        } else if (strcmp(arg, "--tgid") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], 10, &opts.tgid) != 0) {
                fprintf(stderr, "error: invalid --tgid '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--sample") == 0 && i + 1 < argc) {
            if (parse_sample(argv[++i], &opts.sample_stride,
                             opts.sample_rate_str, sizeof(opts.sample_rate_str)) != 0) {
                fprintf(stderr, "error: invalid --sample '%s' (expected 1/N)\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--sample-by") == 0 && i + 1 < argc) {
            const char *sb = argv[++i];
            if (strcmp(sb, "pkt") == 0) opts.sample_by_flow = false;
            else if (strcmp(sb, "flow") == 0) opts.sample_by_flow = true;
            else {
                fprintf(stderr, "error: invalid --sample-by '%s' (expected pkt|flow)\n", sb);
                return 2;
            }
        } else if (strcmp(arg, "--duration") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], &opts.duration_sec) != 0) {
                fprintf(stderr, "error: invalid --duration '%s'\n", argv[i]);
                return 2;
            }
            duration_set = true;
        } else if (strcmp(arg, "--mem-budget") == 0 && i + 1 < argc) {
            if (parse_budget_bytes(argv[++i], &opts.mem_budget_bytes) != 0) {
                fprintf(stderr, "error: invalid --mem-budget '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--disk-budget") == 0 && i + 1 < argc) {
            if (parse_budget_bytes(argv[++i], &opts.disk_budget_bytes) != 0) {
                fprintf(stderr, "error: invalid --disk-budget '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--trigger") == 0 && i + 1 < argc) {
            if (parse_trigger(argv[++i], &opts) != 0) {
                fprintf(stderr, "error: invalid --trigger '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--pre-window") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], &opts.pre_window_sec) != 0) {
                fprintf(stderr, "error: invalid --pre-window '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--post-window") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], &opts.post_window_sec) != 0) {
                fprintf(stderr, "error: invalid --post-window '%s'\n", argv[i]);
                return 2;
            }
        } else if (strcmp(arg, "--profile") == 0 && i + 1 < argc) {
            const char *pr = argv[++i];
            if (strcmp(pr, "sendmsg") == 0) opts.profile_sendmsg = true;
            else if (strcmp(pr, "default") == 0 || strcmp(pr, "off") == 0) opts.profile_sendmsg = false;
            else {
                fprintf(stderr, "error: invalid --profile '%s'\n", pr);
                return 2;
            }
        } else if (strcmp(arg, "--plugin") == 0 && i + 1 < argc) {
            if (opts.num_plugin_paths >= DEV_MAX_PLUGIN_PATHS) {
                fprintf(stderr, "error: too many --plugin flags (max %d)\n", DEV_MAX_PLUGIN_PATHS);
                return 2;
            }
            snprintf(opts.plugin_paths[opts.num_plugin_paths++],
                     sizeof(opts.plugin_paths[0]), "%s", argv[++i]);
        } else if (strcmp(arg, "--plugin-dir") == 0 && i + 1 < argc) {
            snprintf(opts.plugin_dir, sizeof(opts.plugin_dir), "%s", argv[++i]);
        } else if (strcmp(arg, "--capture-hdr") == 0 && i + 1 < argc) {
            uint64_t cl;
            if (parse_unsigned(argv[++i], 10, UINT64_MAX, &cl) != 0) {
                fprintf(stderr, "error: invalid --capture-hdr '%s'\n", argv[i]);
                return 2;
            }
            if (cl > 128U) cl = 128U; /* preserve existing saturation */
            opts.capture_hdr_len = (uint32_t)cl;
        } else if (strcmp(arg, "--probe-groups") == 0 && i + 1 < argc) {
            char gerr[128] = {0};
            if (pkt_parse_probe_groups_csv(argv[++i], &opts.requested_groups_mask,
                                           gerr, sizeof(gerr)) != 0) {
                fprintf(stderr, "error: invalid --probe-groups: %s\n", gerr);
                return 2;
            }
            opts.has_probe_groups = true;
        } else if (strcmp(arg, "--preset") == 0 && i + 1 < argc) {
            const char *ps = argv[++i];
            if (pkt_preset_mask_from_name(ps, &opts.requested_groups_mask) != 0) {
                fprintf(stderr, "error: invalid --preset '%s' (expected egress|drop-pwru|full-path|tcp-diag)\n", ps);
                return 2;
            }
            snprintf(opts.probe_preset, sizeof(opts.probe_preset), "%s", ps);
            opts.has_preset = true;
        } else if (strcmp(arg, "--preset-label") == 0 && i + 1 < argc) {
            const char *pl = argv[++i];
            if (strcmp(pl, "egress") != 0 && strcmp(pl, "drop-pwru") != 0 &&
                strcmp(pl, "full-path") != 0 && strcmp(pl, "tcp-diag") != 0 &&
                strcmp(pl, "custom") != 0) {
                fprintf(stderr, "error: invalid --preset-label '%s'\n", pl);
                return 2;
            }
            snprintf(opts.probe_preset, sizeof(opts.probe_preset), "%s", pl);
        } else if (strcmp(arg, "--out") == 0 && i + 1 < argc) {
            snprintf(opts.out_dir, sizeof(opts.out_dir), "%s", argv[++i]);
        } else {
            fprintf(stderr, "error: unrecognized or incomplete option '%s'\n", arg);
            print_usage(stderr);
            return 2;
        }
    }

    /* Wave 3 CLI mutual exclusion: --preset and --probe-groups cannot be combined */
    if (opts.has_preset && opts.has_probe_groups) {
        fprintf(stderr, "error: --preset and --probe-groups are mutually exclusive\n");
        return 2;
    }
    if (!opts.has_preset && !opts.has_probe_groups) {
        opts.requested_groups_mask = PKT_PRESET_EGRESS_MASK;
        if (!opts.probe_preset[0])
            snprintf(opts.probe_preset, sizeof(opts.probe_preset), "egress");
    } else if (!opts.probe_preset[0]) {
        snprintf(opts.probe_preset, sizeof(opts.probe_preset), "custom");
    }
    /* core_drop is always required in effective_groups */
    opts.effective_groups_mask = opts.requested_groups_mask | PKT_GRP_CORE_DROP;

    if (!opts.dev_name[0]) {
        fprintf(stderr, "error: --dev <ifname> is required\n");
        return 2;
    }

    if (opts.is_record) {
        if (!opts.out_dir[0]) {
            fprintf(stderr, "error: --out <dir> is required for 'record'\n");
            return 2;
        }
        if (opts.mode == MODE_DAEMON && !duration_set) {
            opts.duration_sec = 0; /* run until SIGINT/SIGTERM unless --duration set */
        }
        return run_record(&opts);
    }

    return run_inspect(&opts);
}
