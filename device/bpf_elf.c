#define _GNU_SOURCE
#include "device_common.h"
#include "../include/pktpath_bpf.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ==========================================================================
 * Wave 3 Probe Groups (9) & Presets (4 + custom)
 * ========================================================================== */

static const char *const k_group_names[PKT_GRP_COUNT] = {
    "core_drop",
    "egress_tc",
    "sock_app",
    "ingress_rx",
    "l3_route",
    "netfilter_nat",
    "tcp_diag",
    "drop_stack",
    "tcp_probe",
};

uint32_t pkt_group_bit_from_name(const char *name) {
    if (!name || !name[0]) return 0;
    for (unsigned i = 0; i < PKT_GRP_COUNT; i++) {
        if (strcmp(name, k_group_names[i]) == 0)
            return 1U << i;
    }
    return 0;
}

const char *pkt_group_name_from_index(unsigned idx) {
    if (idx >= PKT_GRP_COUNT) return NULL;
    return k_group_names[idx];
}

int pkt_preset_mask_from_name(const char *preset, uint32_t *mask_out) {
    if (!preset || !mask_out) return -1;
    if (strcmp(preset, "egress") == 0) {
        *mask_out = PKT_PRESET_EGRESS_MASK;
        return 0;
    }
    if (strcmp(preset, "drop-pwru") == 0) {
        *mask_out = PKT_PRESET_DROP_PWRU_MASK;
        return 0;
    }
    if (strcmp(preset, "full-path") == 0) {
        *mask_out = PKT_PRESET_FULL_PATH_MASK;
        return 0;
    }
    if (strcmp(preset, "tcp-diag") == 0) {
        *mask_out = PKT_PRESET_TCP_DIAG_MASK;
        return 0;
    }
    return -1;
}

int pkt_parse_probe_groups_csv(const char *csv, uint32_t *mask_out, char *err_buf, size_t err_cap) {
    if (!csv || !csv[0] || !mask_out) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "empty --probe-groups list");
        return -1;
    }
    uint32_t mask = 0;
    const char *p = csv;
    while (*p) {
        while (*p == ',' || isspace((unsigned char)*p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',' && !isspace((unsigned char)*p)) p++;
        size_t len = (size_t)(p - start);
        if (len == 0 || len >= 32) {
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid probe group token");
            return -1;
        }
        char tok[32];
        memcpy(tok, start, len);
        tok[len] = '\0';
        uint32_t bit = pkt_group_bit_from_name(tok);
        if (bit == 0) {
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "unknown probe group '%s'", tok);
            return -1;
        }
        mask |= bit;
    }
    if (mask == 0) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "no valid probe groups specified");
        return -1;
    }
    *mask_out = mask;
    return 0;
}

const char *probe_inv_status_str(enum probe_inv_status st) {
    switch (st) {
    case PROBE_ST_ATTACHED:              return "attached";
    case PROBE_ST_DISABLED_BY_USER:      return "disabled_by_user";
    case PROBE_ST_UNAVAILABLE_IN_KERNEL: return "unavailable_in_kernel";
    case PROBE_ST_ATTACH_FAILED:         return "attach_failed";
    default:                             return "attach_failed";
    }
}

/* ==========================================================================
 * Pure-C FIPS 180-4 SHA-256 (zero external crypto library dependency)
 * ========================================================================== */

struct sha256_ctx {
    uint32_t h[8];
    uint64_t total_bits;
    uint8_t  buf[64];
    size_t   buf_len;
};

static const uint32_t k_sha256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32U - n));
}

static void sha256_init(struct sha256_ctx *c) {
    c->h[0] = 0x6a09e667U; c->h[1] = 0xbb67ae85U;
    c->h[2] = 0x3c6ef372U; c->h[3] = 0xa54ff53aU;
    c->h[4] = 0x510e527fU; c->h[5] = 0x9b05688cU;
    c->h[6] = 0x1f83d9abU; c->h[7] = 0x5be0cd19U;
    c->total_bits = 0;
    c->buf_len = 0;
}

static void sha256_compress(struct sha256_ctx *c, const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k_sha256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_update(struct sha256_ctx *c, const uint8_t *data, size_t len) {
    c->total_bits += (uint64_t)len * 8ULL;
    while (len > 0) {
        size_t take = 64U - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take;
        data += take;
        len -= take;
        if (c->buf_len == 64U) {
            sha256_compress(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final_hex(struct sha256_ctx *c, char hex_out[65]) {
    uint64_t bits = c->total_bits;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    while (c->buf_len != 56U) {
        uint8_t z = 0;
        sha256_update(c, &z, 1);
    }
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++)
        len_be[7 - i] = (uint8_t)((bits >> (i * 8)) & 0xFFU);
    /* Compress final block directly without altering total_bits */
    memcpy(c->buf + 56, len_be, 8);
    sha256_compress(c, c->buf);

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        uint32_t v = c->h[i];
        for (int j = 0; j < 8; j++) {
            hex_out[i * 8 + j] = hex[(v >> (28 - j * 4)) & 0xFU];
        }
    }
    hex_out[64] = '\0';
}

void pkt_sha256_bytes(const uint8_t *data, size_t len, char hex_out[65]) {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    if (data && len > 0) sha256_update(&ctx, data, len);
    sha256_final_hex(&ctx, hex_out);
}

int pkt_sha256_file(const char *path, char hex_out[65], size_t *size_out, char *err_buf, size_t err_cap) {
    if (!path || !hex_out) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "open(%s) failed: %s", path, strerror(errno));
        return -1;
    }
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[8192];
    size_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "read(%s) failed: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
        if (total > DEV_MAX_BPF_OBJ_BYTES) {
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "object exceeds %u byte limit", DEV_MAX_BPF_OBJ_BYTES);
            close(fd);
            return -1;
        }
        sha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    sha256_final_hex(&ctx, hex_out);
    if (size_out) *size_out = total;
    return 0;
}

/* ==========================================================================
 * Minimal Zero-libbpf ELF64-BPF Parser & Strict Whitelist Relocator
 * ========================================================================== */

#define PKT_ELF_EM_BPF         247U
#define PKT_ELF_SHT_PROGBITS   1U
#define PKT_ELF_SHT_SYMTAB     2U
#define PKT_ELF_SHT_STRTAB     3U
#define PKT_ELF_SHT_RELA       4U
#define PKT_ELF_SHT_REL        9U
#define PKT_ELF_SHF_EXECINSTR  0x4ULL
#define PKT_R_BPF_64_64        1U

#define PKT_BPF_LD_IMM64_OP    0x18U
#define PKT_BPF_PSEUDO_MAP_FD  1U

struct elf64_ehdr_raw {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct elf64_shdr_raw {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct elf64_sym_raw {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct elf64_rel_raw {
    uint64_t r_offset;
    uint64_t r_info;
};

struct raw_bpf_insn {
    uint8_t code;
    uint8_t regs; /* dst_reg:4 | src_reg:4 */
    int16_t off;
    int32_t imm;
};

static const char *elf_str_at(const uint8_t *elf, size_t elf_len,
                              const struct elf64_shdr_raw *strtab, uint32_t off) {
    if (!strtab || strtab->sh_offset > elf_len || strtab->sh_size > elf_len - strtab->sh_offset)
        return NULL;
    if (off >= strtab->sh_size) return NULL;
    const char *base = (const char *)(elf + strtab->sh_offset + off);
    size_t max_len = (size_t)(strtab->sh_size - off);
    if (!memchr(base, '\0', max_len)) return NULL;
    return base;
}

static bool is_forbidden_data_section(const char *sec_name) {
    if (!sec_name) return false;
    return strcmp(sec_name, ".rodata") == 0 || strncmp(sec_name, ".rodata.", 8) == 0 ||
           strcmp(sec_name, ".data") == 0   || strncmp(sec_name, ".data.", 6) == 0 ||
           strcmp(sec_name, ".bss") == 0    || strncmp(sec_name, ".bss.", 5) == 0;
}

int bpf_elf_extract_and_relocate(const uint8_t *elf_data, size_t elf_len,
                                 const char *sec_name,
                                 int rb_fd, int btf_off_fd, int plugin_cfg_fd,
                                 uint16_t site_id,
                                 struct ext_bpf_prog_buf *out,
                                 char *err_buf, size_t err_cap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!elf_data || !sec_name || !sec_name[0] || !out) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid arguments to bpf_elf_extract_and_relocate");
        return -1;
    }
    if (site_id < PKT_SITE_EXT_MIN || site_id > PKT_SITE_EXT_MAX) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "site_id 0x%x outside external range [0x2000,0xFFFE]", site_id);
        return -1;
    }
    if (elf_len < sizeof(struct elf64_ehdr_raw) || elf_len > DEV_MAX_BPF_OBJ_BYTES) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid ELF size %zu", elf_len);
        return -1;
    }

    struct elf64_ehdr_raw eh;
    memcpy(&eh, elf_data, sizeof(eh));
    if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' || eh.e_ident[2] != 'L' || eh.e_ident[3] != 'F') {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "not an ELF file");
        return -1;
    }
    if (eh.e_ident[4] != 2U || eh.e_ident[5] != 1U) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "expected ELF64 little-endian");
        return -1;
    }
    if (eh.e_machine != PKT_ELF_EM_BPF) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid e_machine %u (expected EM_BPF=247)", eh.e_machine);
        return -1;
    }
    if (eh.e_shnum == 0 || eh.e_shnum > 4096U || eh.e_shentsize < sizeof(struct elf64_shdr_raw)) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid ELF section table header");
        return -1;
    }
    if (eh.e_shoff > elf_len || (uint64_t)eh.e_shnum * eh.e_shentsize > elf_len - eh.e_shoff) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "ELF section table out of bounds");
        return -1;
    }
    if (eh.e_shstrndx >= eh.e_shnum) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid e_shstrndx");
        return -1;
    }

    struct elf64_shdr_raw shstr;
    memcpy(&shstr, elf_data + eh.e_shoff + (size_t)eh.e_shstrndx * eh.e_shentsize, sizeof(shstr));

    /* Locate target program section */
    int target_shndx = -1;
    struct elf64_shdr_raw target_sh;
    memset(&target_sh, 0, sizeof(target_sh));
    for (uint16_t i = 0; i < eh.e_shnum; i++) {
        struct elf64_shdr_raw sh;
        memcpy(&sh, elf_data + eh.e_shoff + (size_t)i * eh.e_shentsize, sizeof(sh));
        const char *sname = elf_str_at(elf_data, elf_len, &shstr, sh.sh_name);
        if (sname && strcmp(sname, sec_name) == 0) {
            target_shndx = (int)i;
            target_sh = sh;
            break;
        }
    }
    if (target_shndx < 0) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "section '%s' not found in ELF", sec_name);
        return -1;
    }
    if (target_sh.sh_type != PKT_ELF_SHT_PROGBITS ||
        (target_sh.sh_flags & PKT_ELF_SHF_EXECINSTR) == 0 ||
        target_sh.sh_size == 0 || (target_sh.sh_size % sizeof(struct raw_bpf_insn)) != 0) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "section '%s' is not valid BPF code", sec_name);
        return -1;
    }
    if (target_sh.sh_offset > elf_len || target_sh.sh_size > elf_len - target_sh.sh_offset) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "section '%s' out of bounds", sec_name);
        return -1;
    }

    uint32_t insn_cnt = (uint32_t)(target_sh.sh_size / sizeof(struct raw_bpf_insn));
    struct raw_bpf_insn *insns = malloc((size_t)target_sh.sh_size);
    if (!insns) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "out of memory allocating BPF insns");
        return -1;
    }
    memcpy(insns, elf_data + target_sh.sh_offset, (size_t)target_sh.sh_size);

    /* Patch PKT_SITE_EXT_SENTINEL before relocations */
    uint32_t site_patched = 0;
    for (uint32_t k = 0; k < insn_cnt; k++) {
        if (insns[k].code == PKT_BPF_LD_IMM64_OP) {
            if (k + 1 < insn_cnt) k++;
            continue;
        }
        if (insns[k].imm == (int32_t)PKT_SITE_EXT_SENTINEL) {
            insns[k].imm = (int32_t)site_id;
            site_patched++;
        }
    }

    /* Validate and apply relocations targeting target_shndx */
    uint32_t reloc_applied = 0;
    for (uint16_t i = 0; i < eh.e_shnum; i++) {
        struct elf64_shdr_raw rsh;
        memcpy(&rsh, elf_data + eh.e_shoff + (size_t)i * eh.e_shentsize, sizeof(rsh));
        if (rsh.sh_info != (uint32_t)target_shndx)
            continue;
        if (rsh.sh_type == PKT_ELF_SHT_RELA) {
            free(insns);
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "unsupported SHT_RELA relocation in '%s'", sec_name);
            return -1;
        }
        if (rsh.sh_type != PKT_ELF_SHT_REL)
            continue;

        if (rsh.sh_link >= eh.e_shnum || rsh.sh_offset > elf_len || rsh.sh_size > elf_len - rsh.sh_offset) {
            free(insns);
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "relocation section out of bounds in '%s'", sec_name);
            return -1;
        }
        struct elf64_shdr_raw sym_sh;
        memcpy(&sym_sh, elf_data + eh.e_shoff + (size_t)rsh.sh_link * eh.e_shentsize, sizeof(sym_sh));
        if (sym_sh.sh_type != PKT_ELF_SHT_SYMTAB || sym_sh.sh_link >= eh.e_shnum ||
            sym_sh.sh_offset > elf_len || sym_sh.sh_size > elf_len - sym_sh.sh_offset) {
            free(insns);
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid symtab linked by reloc in '%s'", sec_name);
            return -1;
        }
        struct elf64_shdr_raw symstr_sh;
        memcpy(&symstr_sh, elf_data + eh.e_shoff + (size_t)sym_sh.sh_link * eh.e_shentsize, sizeof(symstr_sh));

        size_t rel_entsz = rsh.sh_entsize ? (size_t)rsh.sh_entsize : sizeof(struct elf64_rel_raw);
        size_t sym_entsz = sym_sh.sh_entsize ? (size_t)sym_sh.sh_entsize : sizeof(struct elf64_sym_raw);
        if (rel_entsz < sizeof(struct elf64_rel_raw) || sym_entsz < sizeof(struct elf64_sym_raw)) {
            free(insns);
            if (err_buf && err_cap) snprintf(err_buf, err_cap, "invalid rel/sym entry size");
            return -1;
        }
        size_t nrels = (size_t)(rsh.sh_size / rel_entsz);
        size_t nsyms = (size_t)(sym_sh.sh_size / sym_entsz);

        for (size_t r = 0; r < nrels; r++) {
            struct elf64_rel_raw rel;
            memcpy(&rel, elf_data + rsh.sh_offset + r * rel_entsz, sizeof(rel));
            uint32_t r_type = (uint32_t)(rel.r_info & 0xFFFFFFFFULL);
            uint32_t sym_idx = (uint32_t)(rel.r_info >> 32);

            if (r_type != PKT_R_BPF_64_64) {
                free(insns);
                if (err_buf && err_cap) snprintf(err_buf, err_cap, "unsupported relocation type %u in '%s'", r_type, sec_name);
                return -1;
            }
            if ((rel.r_offset % sizeof(struct raw_bpf_insn)) != 0 ||
                rel.r_offset / sizeof(struct raw_bpf_insn) >= insn_cnt) {
                free(insns);
                if (err_buf && err_cap) snprintf(err_buf, err_cap, "relocation offset out of bounds in '%s'", sec_name);
                return -1;
            }
            if (sym_idx >= nsyms) {
                free(insns);
                if (err_buf && err_cap) snprintf(err_buf, err_cap, "relocation symbol index %u out of bounds", sym_idx);
                return -1;
            }

            struct elf64_sym_raw sym;
            memcpy(&sym, elf_data + sym_sh.sh_offset + (size_t)sym_idx * sym_entsz, sizeof(sym));
            const char *sym_name = elf_str_at(elf_data, elf_len, &symstr_sh, sym.st_name);
            const char *sym_sec = NULL;
            if (sym.st_shndx < eh.e_shnum) {
                struct elf64_shdr_raw ssec;
                memcpy(&ssec, elf_data + eh.e_shoff + (size_t)sym.st_shndx * eh.e_shentsize, sizeof(ssec));
                sym_sec = elf_str_at(elf_data, elf_len, &shstr, ssec.sh_name);
            }

            /* Explicitly reject .rodata / .data / .bss relocations */
            if (is_forbidden_data_section(sym_sec) || is_forbidden_data_section(sym_name)) {
                free(insns);
                if (err_buf && err_cap)
                    snprintf(err_buf, err_cap, "forbidden data/rodata/bss relocation (%s in %s) rejected",
                             sym_name ? sym_name : "<anon>", sym_sec ? sym_sec : "<unknown>");
                return -1;
            }

            /* Strict 3-map whitelist: ONLY rb, btf_off, plugin_cfg */
            int target_fd = -1;
            if (sym_name && strcmp(sym_name, "rb") == 0) {
                target_fd = rb_fd;
            } else if (sym_name && strcmp(sym_name, "btf_off") == 0) {
                target_fd = btf_off_fd;
            } else if (sym_name && strcmp(sym_name, "plugin_cfg") == 0) {
                target_fd = plugin_cfg_fd;
            } else {
                free(insns);
                if (err_buf && err_cap)
                    snprintf(err_buf, err_cap, "forbidden map/symbol relocation '%s' (allowed: rb, btf_off, plugin_cfg)",
                             sym_name ? sym_name : "<unnamed>");
                return -1;
            }

            uint32_t ix = (uint32_t)(rel.r_offset / sizeof(struct raw_bpf_insn));
            if (insns[ix].code != PKT_BPF_LD_IMM64_OP || ix + 1 >= insn_cnt) {
                free(insns);
                if (err_buf && err_cap)
                    snprintf(err_buf, err_cap, "relocation at insn %u is not LD_IMM64", ix);
                return -1;
            }
            insns[ix].regs = (uint8_t)((insns[ix].regs & 0x0FU) | (PKT_BPF_PSEUDO_MAP_FD << 4));
            insns[ix].imm  = target_fd;
            reloc_applied++;
        }
    }

    out->insns = insns;
    out->insn_cnt = insn_cnt;
    out->reloc_applied = reloc_applied;
    out->site_patched = site_patched;
    return 0;
}

/* ==========================================================================
 * Minimal JSON Helpers & <plugin_dir>/<plugin_id>/bundle.json Scanner
 * ========================================================================== */

static const char *skip_ws(const char *p) {
    while (p && *p && isspace((unsigned char)*p)) p++;
    return p;
}

static bool extract_json_str(const char *obj, const char *end, const char *key,
                             char *out, size_t cap) {
    if (!obj || !key || !out || cap == 0) return false;
    out[0] = '\0';
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = obj;
    while ((p = strstr(p, pat)) != NULL) {
        if (end && p >= end) return false;
        p += strlen(pat);
        p = skip_ws(p);
        if (*p != ':') continue;
        p = skip_ws(p + 1);
        if (*p != '"') return false;
        p++;
        size_t n = 0;
        while (*p && *p != '"' && (!end || p < end)) {
            if (*p == '\\' && p[1]) p++;
            if (n + 1 < cap) out[n++] = *p;
            p++;
        }
        out[n] = '\0';
        return (*p == '"');
    }
    return false;
}

static bool extract_json_u32(const char *obj, const char *end, const char *key, uint32_t *val_out) {
    if (!obj || !key || !val_out) return false;
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = obj;
    while ((p = strstr(p, pat)) != NULL) {
        if (end && p >= end) return false;
        p += strlen(pat);
        p = skip_ws(p);
        if (*p != ':') continue;
        p = skip_ws(p + 1);
        if (!isdigit((unsigned char)*p)) return false;
        *val_out = (uint32_t)strtoul(p, NULL, 10);
        return true;
    }
    return false;
}

static const char *normalize_host_arch(const char *uname_m) {
    if (!uname_m) return "";
    if (strcmp(uname_m, "aarch64") == 0 || strcmp(uname_m, "arm64") == 0) return "arm64";
    if (strcmp(uname_m, "x86_64") == 0 || strcmp(uname_m, "amd64") == 0) return "x86_64";
    return uname_m;
}

static bool hex_equal_ci(const char *a, const char *b) {
    if (!a || !b || strlen(a) != 64 || strlen(b) != 64) return false;
    for (int i = 0; i < 64; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    }
    return true;
}

static void parse_one_bundle(const char *subdir_path, const char *bundle_path,
                             const char *host_arch, struct ext_bpf_bundle *b) {
    memset(b, 0, sizeof(*b));
    FILE *fp = fopen(bundle_path, "rb");
    if (!fp) {
        snprintf(b->error, sizeof(b->error), "cannot open %s: %s", bundle_path, strerror(errno));
        return;
    }
    char *buf = malloc(128U * 1024U);
    if (!buf) {
        fclose(fp);
        snprintf(b->error, sizeof(b->error), "oom reading bundle.json");
        return;
    }
    size_t n = fread(buf, 1, 128U * 1024U - 1U, fp);
    fclose(fp);
    buf[n] = '\0';

    extract_json_str(buf, buf + n, "plugin_id", b->plugin_id, sizeof(b->plugin_id));
    extract_json_u32(buf, buf + n, "abi_version", &b->abi_version);
    extract_json_str(buf, buf + n, "arch", b->arch, sizeof(b->arch));
    extract_json_str(buf, buf + n, "object", b->object_rel, sizeof(b->object_rel));
    extract_json_str(buf, buf + n, "sha256", b->expected_sha256, sizeof(b->expected_sha256));

    /* Parse optional enabled_groups array */
    const char *eg = strstr(buf, "\"enabled_groups\"");
    if (eg) {
        const char *lb = strchr(eg, '[');
        const char *rb = lb ? strchr(lb, ']') : NULL;
        if (lb && rb) {
            const char *p = lb + 1;
            while (p < rb) {
                const char *q1 = strchr(p, '"');
                if (!q1 || q1 >= rb) break;
                const char *q2 = strchr(q1 + 1, '"');
                if (!q2 || q2 >= rb) break;
                size_t len = (size_t)(q2 - (q1 + 1));
                if (len > 0 && len < 32) {
                    char g[32];
                    memcpy(g, q1 + 1, len);
                    g[len] = '\0';
                    b->enabled_groups_mask |= pkt_group_bit_from_name(g);
                }
                p = q2 + 1;
            }
        }
    }

    /* Parse hooks array (max DEV_MAX_EXT_HOOKS) */
    const char *hk = strstr(buf, "\"hooks\"");
    if (hk) {
        const char *lb = strchr(hk, '[');
        const char *rb = lb ? strchr(lb, ']') : NULL;
        if (lb && rb) {
            const char *p = lb + 1;
            while (p < rb && b->num_hooks < DEV_MAX_EXT_HOOKS) {
                const char *ob = strchr(p, '{');
                if (!ob || ob >= rb) break;
                const char *cb = strchr(ob, '}');
                if (!cb || cb >= rb) break;
                struct ext_bpf_hook *h = &b->hooks[b->num_hooks];
                memset(h, 0, sizeof(*h));
                extract_json_str(ob, cb, "id", h->id, sizeof(h->id));
                extract_json_str(ob, cb, "group", h->group, sizeof(h->group));
                extract_json_str(ob, cb, "sec", h->sec, sizeof(h->sec));
                extract_json_str(ob, cb, "type", h->type, sizeof(h->type));
                extract_json_str(ob, cb, "target", h->target, sizeof(h->target));
                extract_json_str(ob, cb, "stage", h->stage, sizeof(h->stage));
                h->group_bit = pkt_group_bit_from_name(h->group);
                if (h->sec[0] && h->target[0]) {
                    if (!h->id[0]) { char tmp_id[96]; snprintf(tmp_id, sizeof(tmp_id), "ext.%s.%s", b->plugin_id, h->sec); memcpy(h->id, tmp_id, sizeof(h->id)); }
                    b->num_hooks++;
                }
                p = cb + 1;
            }
        }
    }
    free(buf);

    /* Validate bundle contract before allowing any ELF load */
    if (b->abi_version != PKT_PLUGIN_ABI_VERSION) {
        snprintf(b->error, sizeof(b->error), "unsupported abi_version %u (expected %u)",
                 b->abi_version, PKT_PLUGIN_ABI_VERSION);
        return;
    }
    if (!b->plugin_id[0] || !b->object_rel[0]) {
        snprintf(b->error, sizeof(b->error), "bundle.json missing plugin_id or object");
        return;
    }
    if (strstr(b->object_rel, "..") || strchr(b->object_rel, '/') || strchr(b->object_rel, '\\')) {
        snprintf(b->error, sizeof(b->error), "unsafe object filename '%s'", b->object_rel);
        return;
    }
    const char *norm_host = normalize_host_arch(host_arch);
    if (norm_host[0] && b->arch[0] && strcmp(normalize_host_arch(b->arch), norm_host) != 0) {
        snprintf(b->error, sizeof(b->error), "arch mismatch: bundle '%s' != host '%s'", b->arch, norm_host);
        return;
    }

    snprintf(b->object_path, sizeof(b->object_path), "%s/%s", subdir_path, b->object_rel);
    char sha_err[128] = {0};
    if (pkt_sha256_file(b->object_path, b->actual_sha256, NULL, sha_err, sizeof(sha_err)) != 0) {
        snprintf(b->error, sizeof(b->error), "failed hashing %s: %s", b->object_rel, sha_err);
        return;
    }
    if (!hex_equal_ci(b->expected_sha256, b->actual_sha256)) {
        snprintf(b->error, sizeof(b->error), "sha256 mismatch for %s (expected %.12s..., got %.12s...)",
                 b->object_rel, b->expected_sha256, b->actual_sha256);
        return;
    }

    b->valid = true;
}

int bpf_bundle_scan_dir(const char *plugin_dir, const char *host_arch,
                        struct ext_bpf_bundle *out, int max_bundles) {
    if (!plugin_dir || !plugin_dir[0] || !out || max_bundles <= 0)
        return 0;
    DIR *d = opendir(plugin_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_bundles) {
        if (de->d_name[0] == '.') continue;
        char sub[560], bpath[600];
        snprintf(sub, sizeof(sub), "%s/%s", plugin_dir, de->d_name);
        struct stat st;
        if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        snprintf(bpath, sizeof(bpath), "%s/bundle.json", sub);
        if (access(bpath, R_OK) != 0)
            continue;
        parse_one_bundle(sub, bpath, host_arch, &out[count]);
        count++;
    }
    closedir(d);
    return count;
}
