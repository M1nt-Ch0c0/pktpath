#include <elf.h>
#define _GNU_SOURCE
#include "../device/device_common.h"
#include "../include/pktpath_bpf.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint8_t *read_all(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    assert(fp != NULL);
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    assert(sz > 0);
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    assert(buf != NULL);
    assert(fread(buf, 1, (size_t)sz, fp) == (size_t)sz);
    fclose(fp);
    *len_out = (size_t)sz;
    return buf;
}

static void test_sha256_vectors(void) {
    char hex[65];
    pkt_sha256_bytes((const uint8_t *)"abc", 3, hex);
    assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    pkt_sha256_bytes((const uint8_t *)"", 0, hex);
    assert(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    printf("PASS: test_sha256_vectors\n");
}

static void test_real_pwru_objects(const char *path, const char *label) {
    size_t len = 0;
    uint8_t *elf = read_all(path, &len);
    const char *secs[] = {
        "tp_netif_receive_skb", "kp_ip_rcv", "kp_ipv6_rcv", "kp_tcp_v4_rcv", "kp_udp_rcv",
        "kp_ip_route_input_noref", "kp_ip_route_output_flow", "kp_ip_forward",
        "kp_ip_output", "kp_ip6_output", "kp_xfrm_output", "kp_xfrm_input",
        "kp_nf_hook_slow", "kr_nf_hook_slow", "kp_nf_conntrack_in", "kp_nf_nat_packet",
        "tp_tcp_retransmit_skb", "tp_inet_sock_set_state", "tp_tcp_probe",
    };
    for (size_t i = 0; i < sizeof(secs) / sizeof(secs[0]); i++) {
        struct ext_bpf_prog_buf out;
        char err[256] = {0};
        uint16_t sid = (uint16_t)(PKT_SITE_EXT_MIN + i);
        int rc = bpf_elf_extract_and_relocate(elf, len, secs[i], 101, 102, 103, sid, &out, err, sizeof(err));
        if (rc != 0) {
            fprintf(stderr, "FAIL %s sec %s: %s\n", label, secs[i], err);
            exit(1);
        }
        assert(out.insn_cnt > 0);
        assert(out.reloc_applied >= 1);
        assert(out.site_patched >= 1);
        free(out.insns);
    }

    /* site_id outside [0x2000, 0xFFFE] must be rejected */
    struct ext_bpf_prog_buf bad_out;
    char err[256] = {0};
    assert(bpf_elf_extract_and_relocate(elf, len, "kp_ip_rcv", 101, 102, 103, 0x0005, &bad_out, err, sizeof(err)) != 0);

    /* Corrupted e_machine != EM_BPF must be rejected */
    elf[18] = 62; /* EM_X86_64 */
    elf[19] = 0;
    assert(bpf_elf_extract_and_relocate(elf, len, "kp_ip_rcv", 101, 102, 103, 0x2000, &bad_out, err, sizeof(err)) != 0);
    assert(strstr(err, "EM_BPF") != NULL);

    free(elf);
    printf("PASS: test_real_pwru_objects (%s, 19 sections + bounds/EM_BPF checks)\n", label);
}


static void test_btf_export_enum_synthetic(void) {
    /* Build minimal valid binary BTF with BTF_KIND_ENUM("skb_drop_reason") + BTF_KIND_ENUM64("big_enum") */
    const char strs[] = "\0skb_drop_reason\0SKB_DROP_REASON_NOT_SPECIFIED\0SKB_DROP_REASON_NO_SOCKET\0big_enum\0BIG_VAL_1\0";
    uint32_t str_len = (uint32_t)sizeof(strs);
    uint32_t off_enum1 = 1;
    uint32_t off_e1_v1 = 17;
    uint32_t off_e1_v2 = 47;
    uint32_t off_enum2 = 73;
    uint32_t off_e2_v1 = 82;

    uint8_t btf[512];
    memset(btf, 0, sizeof(btf));
    size_t pos = 24; /* hdr_len */

    /* Type 1: BTF_KIND_ENUM (6), vlen=2 */
    uint32_t t1[3] = { off_enum1, (6U << 24) | 2U, 4U };
    memcpy(btf + pos, t1, sizeof(t1)); pos += sizeof(t1);
    uint32_t e1a[2] = { off_e1_v1, 2U };
    uint32_t e1b[2] = { off_e1_v2, 3U };
    memcpy(btf + pos, e1a, sizeof(e1a)); pos += sizeof(e1a);
    memcpy(btf + pos, e1b, sizeof(e1b)); pos += sizeof(e1b);

    /* Type 2: BTF_KIND_ENUM64 (19), vlen=1 */
    uint32_t t2[3] = { off_enum2, (19U << 24) | 1U, 8U };
    memcpy(btf + pos, t2, sizeof(t2)); pos += sizeof(t2);
    uint32_t e2a[3] = { off_e2_v1, 0x00010005U, 0U };
    memcpy(btf + pos, e2a, sizeof(e2a)); pos += sizeof(e2a);

    uint32_t type_len = (uint32_t)(pos - 24);
    memcpy(btf + pos, strs, str_len);
    size_t total = pos + str_len;

    /* Fill BTF header */
    uint16_t magic = 0xEB9FU;
    uint8_t ver = 1, flags = 0;
    uint32_t hdr_len = 24, type_off = 0, str_off = type_len;
    memcpy(btf + 0, &magic, 2);
    btf[2] = ver; btf[3] = flags;
    memcpy(btf + 4, &hdr_len, 4);
    memcpy(btf + 8, &type_off, 4);
    memcpy(btf + 12, &type_len, 4);
    memcpy(btf + 16, &str_off, 4);
    memcpy(btf + 20, &str_len, 4);

    const char *tmp = "/tmp/pktpath_test_synth.btf";
    FILE *fp = fopen(tmp, "wb");
    assert(fp != NULL);
    assert(fwrite(btf, 1, total, fp) == total);
    fclose(fp);

    char err[128] = {0};
    struct btf_db *db = btf_db_load(tmp, err, sizeof(err));
    assert(db != NULL);

    struct btf_enum_entry out[16];
    size_t cnt = 0;
    assert(btf_export_enum(db, "skb_drop_reason", out, 16, &cnt) == 0);
    assert(cnt == 2);
    assert(out[0].value == 2 && strcmp(out[0].name, "SKB_DROP_REASON_NOT_SPECIFIED") == 0);
    assert(out[1].value == 3 && strcmp(out[1].name, "SKB_DROP_REASON_NO_SOCKET") == 0);

    assert(btf_export_enum(db, "big_enum", out, 16, &cnt) == 0);
    assert(cnt == 1);
    assert(out[0].value == 0x00010005LL && strcmp(out[0].name, "BIG_VAL_1") == 0);

    btf_db_free(db);
    unlink(tmp);
    printf("PASS: test_btf_export_enum_synthetic (BTF_KIND_ENUM + BTF_KIND_ENUM64)\n");
}

static void test_bundle_scanner(const char *real_x86_obj, const char *real_sha) {
    const char *root = "/tmp/pktpath_wave3_bundle_test";
    (void)system("rm -rf /tmp/pktpath_wave3_bundle_test");
    mkdir(root, 0755);

    /* 1. Valid bundle */
    mkdir("/tmp/pktpath_wave3_bundle_test/ok_plugin", 0755);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cp %s /tmp/pktpath_wave3_bundle_test/ok_plugin/pwru_probes.bpf.o", real_x86_obj);
    assert(system(cmd) == 0);
    FILE *fp = fopen("/tmp/pktpath_wave3_bundle_test/ok_plugin/bundle.json", "w");
    fprintf(fp, "{\"abi_version\":1,\"plugin_id\":\"ok.pwru\",\"arch\":\"x86_64\",\"object\":\"pwru_probes.bpf.o\",\"sha256\":\"%s\",\"hooks\":[{\"id\":\"h1\",\"group\":\"ingress_rx\",\"sec\":\"kp_ip_rcv\",\"type\":\"kprobe\",\"target\":\"ip_rcv\"}]}", real_sha);
    fclose(fp);

    /* 2. Bad SHA256 bundle */
    mkdir("/tmp/pktpath_wave3_bundle_test/bad_sha", 0755);
    snprintf(cmd, sizeof(cmd), "cp %s /tmp/pktpath_wave3_bundle_test/bad_sha/pwru_probes.bpf.o", real_x86_obj);
    assert(system(cmd) == 0);
    fp = fopen("/tmp/pktpath_wave3_bundle_test/bad_sha/bundle.json", "w");
    fprintf(fp, "{\"abi_version\":1,\"plugin_id\":\"bad.sha\",\"arch\":\"x86_64\",\"object\":\"pwru_probes.bpf.o\",\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"hooks\":[{\"id\":\"h1\",\"group\":\"ingress_rx\",\"sec\":\"kp_ip_rcv\",\"type\":\"kprobe\",\"target\":\"ip_rcv\"}]}");
    fclose(fp);

    /* 3. Arch mismatch bundle */
    mkdir("/tmp/pktpath_wave3_bundle_test/bad_arch", 0755);
    fp = fopen("/tmp/pktpath_wave3_bundle_test/bad_arch/bundle.json", "w");
    fprintf(fp, "{\"abi_version\":1,\"plugin_id\":\"bad.arch\",\"arch\":\"arm64\",\"object\":\"pwru_probes.bpf.o\",\"sha256\":\"%s\",\"hooks\":[]}", real_sha);
    fclose(fp);

    struct ext_bpf_bundle bs[8];
    int n = bpf_bundle_scan_dir(root, "x86_64", bs, 8);
    assert(n == 3);
    int seen_ok = 0, seen_sha = 0, seen_arch = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(bs[i].plugin_id, "ok.pwru") == 0) {
            assert(bs[i].valid);
            assert(bs[i].num_hooks == 1);
            seen_ok = 1;
        } else if (strcmp(bs[i].plugin_id, "bad.sha") == 0) {
            assert(!bs[i].valid);
            assert(strstr(bs[i].error, "sha256 mismatch") != NULL);
            seen_sha = 1;
        } else if (strcmp(bs[i].plugin_id, "bad.arch") == 0) {
            assert(!bs[i].valid);
            assert(strstr(bs[i].error, "arch mismatch") != NULL);
            seen_arch = 1;
        }
    }
    assert(seen_ok && seen_sha && seen_arch);
    (void)system("rm -rf /tmp/pktpath_wave3_bundle_test");
    printf("PASS: test_bundle_scanner (valid + forged sha256 + arch mismatch)\n");
}


static void test_adversarial_elf_synthetic(const char *target_sec_name,
                                           const char *sym_name,
                                           const char *expect_substr,
                                           const char *label) {
    /* Build a minimal valid ELF64 LE EM_BPF object in memory:
     *   sec 0: NULL
     *   sec 1: .shstrtab
     *   sec 2: .strtab
     *   sec 3: .symtab (2 entries: null + sym pointing to sec 4)
     *   sec 4: <target_sec_name> (".rodata" or "maps")
     *   sec 5: kp_adv (3 BPF insns: LD_IMM64 (16B) + EXIT (8B))
     *   sec 6: .relkp_adv (1 Elf64_Rel referencing sym 1 at offset 0)
     */
    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    char shstr[256];
    size_t shlen = 1; /* leading NUL */
    uint32_t off_shstr   = (uint32_t)shlen; strcpy(shstr + shlen, ".shstrtab"); shlen += strlen(".shstrtab") + 1;
    uint32_t off_strtab  = (uint32_t)shlen; strcpy(shstr + shlen, ".strtab");   shlen += strlen(".strtab") + 1;
    uint32_t off_symtab  = (uint32_t)shlen; strcpy(shstr + shlen, ".symtab");   shlen += strlen(".symtab") + 1;
    uint32_t off_target  = (uint32_t)shlen; strcpy(shstr + shlen, target_sec_name); shlen += strlen(target_sec_name) + 1;
    uint32_t off_prog    = (uint32_t)shlen; strcpy(shstr + shlen, "kp_adv");    shlen += strlen("kp_adv") + 1;
    uint32_t off_rel     = (uint32_t)shlen; strcpy(shstr + shlen, ".relkp_adv"); shlen += strlen(".relkp_adv") + 1;

    char strtab[128];
    size_t stlen = 1;
    uint32_t off_sym = (uint32_t)stlen; strcpy(strtab + stlen, sym_name); stlen += strlen(sym_name) + 1;

    Elf64_Sym syms[2];
    memset(syms, 0, sizeof(syms));
    syms[1].st_name  = off_sym;
    syms[1].st_info  = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    syms[1].st_shndx = 4; /* target_sec_name */
    syms[1].st_value = 0;
    syms[1].st_size  = 16;

    uint8_t target_data[16] = {0};

    /* 3 BPF insns: LD_IMM64 (opcode 0x18, 2 insns) + EXIT (opcode 0x95) */
    uint8_t insns[24];
    memset(insns, 0, sizeof(insns));
    insns[0] = 0x18; /* BPF_LD | BPF_DW | BPF_IMM */
    insns[16] = 0x95; /* BPF_JMP | BPF_EXIT */

    Elf64_Rel rel;
    rel.r_offset = 0;
    rel.r_info   = ELF64_R_INFO(1, 1); /* sym 1, R_BPF_64_64 */

    size_t cur = sizeof(Elf64_Ehdr);
    size_t shstr_off = cur; memcpy(buf + cur, shstr, shlen); cur = (cur + shlen + 7) & ~7ULL;
    size_t str_off   = cur; memcpy(buf + cur, strtab, stlen); cur = (cur + stlen + 7) & ~7ULL;
    size_t sym_off   = cur; memcpy(buf + cur, syms, sizeof(syms)); cur = (cur + sizeof(syms) + 7) & ~7ULL;
    size_t tgt_off   = cur; memcpy(buf + cur, target_data, sizeof(target_data)); cur = (cur + sizeof(target_data) + 7) & ~7ULL;
    size_t prg_off   = cur; memcpy(buf + cur, insns, sizeof(insns)); cur = (cur + sizeof(insns) + 7) & ~7ULL;
    size_t rel_off   = cur; memcpy(buf + cur, &rel, sizeof(rel)); cur = (cur + sizeof(rel) + 7) & ~7ULL;
    size_t shdr_off  = cur;

    Elf64_Shdr sh[7];
    memset(sh, 0, sizeof(sh));
    sh[1].sh_name = off_shstr;  sh[1].sh_type = SHT_STRTAB;   sh[1].sh_offset = shstr_off; sh[1].sh_size = shlen;
    sh[2].sh_name = off_strtab; sh[2].sh_type = SHT_STRTAB;   sh[2].sh_offset = str_off;   sh[2].sh_size = stlen;
    sh[3].sh_name = off_symtab; sh[3].sh_type = SHT_SYMTAB;   sh[3].sh_offset = sym_off;   sh[3].sh_size = sizeof(syms);
    sh[3].sh_link = 2;          sh[3].sh_entsize = sizeof(Elf64_Sym);
    sh[4].sh_name = off_target; sh[4].sh_type = SHT_PROGBITS; sh[4].sh_offset = tgt_off;   sh[4].sh_size = sizeof(target_data);
    sh[5].sh_name = off_prog;   sh[5].sh_type = SHT_PROGBITS; sh[5].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh[5].sh_offset = prg_off;  sh[5].sh_size = sizeof(insns);
    sh[6].sh_name = off_rel;    sh[6].sh_type = SHT_REL;      sh[6].sh_offset = rel_off;   sh[6].sh_size = sizeof(rel);
    sh[6].sh_link = 3;          sh[6].sh_info = 5;            sh[6].sh_entsize = sizeof(Elf64_Rel);

    memcpy(buf + shdr_off, sh, sizeof(sh));
    size_t total = shdr_off + sizeof(sh);

    Elf64_Ehdr eh;
    memset(&eh, 0, sizeof(eh));
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA]  = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type      = ET_REL;
    eh.e_machine   = 247; /* EM_BPF */
    eh.e_version   = EV_CURRENT;
    eh.e_shoff     = shdr_off;
    eh.e_ehsize    = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum     = 7;
    eh.e_shstrndx  = 1;
    memcpy(buf, &eh, sizeof(eh));

    struct ext_bpf_prog_buf out;
    char err[256] = {0};
    int rc = bpf_elf_extract_and_relocate(buf, total, "kp_adv", 10, 11, 12,
                                          0x2000U, &out, err, sizeof(err));
    assert(rc != 0);
    assert(strstr(err, expect_substr) != NULL);
    printf("PASS: test_adversarial_elf_synthetic (%s -> %s)\n", label, err);
}

int main(void) {
    test_sha256_vectors();
    test_real_pwru_objects("plugins/official/pktpath-pwru-probes/bpf/arm64/pwru_probes.bpf.o", "arm64");
    test_real_pwru_objects("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o", "x86_64");
    test_adversarial_elf_synthetic(".rodata", "forbidden_tbl", "rodata", "rodata rejection");
    test_adversarial_elf_synthetic("maps", "control", "forbidden map/symbol", "control map rejection");
    test_btf_export_enum_synthetic();

    char x86_sha[65] = {0};
    assert(pkt_sha256_file("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o",
                           x86_sha, NULL, NULL, 0) == 0);
    test_bundle_scanner("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o", x86_sha);
    printf("ALL WAVE 3 C UNIT TESTS PASSED!\n");
    return 0;
}
