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

static void test_adversarial_elf(const char *path, const char *sec, const char *expect_substr, const char *label) {
    size_t len = 0;
    uint8_t *elf = read_all(path, &len);
    struct ext_bpf_prog_buf out;
    char err[256] = {0};
    int rc = bpf_elf_extract_and_relocate(elf, len, sec, 101, 102, 103, 0x2000, &out, err, sizeof(err));
    free(elf);
    if (rc == 0) {
        fprintf(stderr, "FAIL: %s should have been rejected!\n", label);
        free(out.insns);
        exit(1);
    }
    if (strstr(err, expect_substr) == NULL) {
        fprintf(stderr, "FAIL: %s err='%s' did not contain '%s'\n", label, err, expect_substr);
        exit(1);
    }
    printf("PASS: test_adversarial_elf (%s -> %s)\n", label, err);
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

int main(void) {
    test_sha256_vectors();
    test_real_pwru_objects("plugins/official/pktpath-pwru-probes/bpf/arm64/pwru_probes.bpf.o", "arm64");
    test_real_pwru_objects("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o", "x86_64");
    test_adversarial_elf("/tmp/adv_rodata.bpf.o", "kp_bad_rodata", "rodata", "rodata rejection");
    test_adversarial_elf("/tmp/adv_control.bpf.o", "kp_bad_ctrl", "forbidden map/symbol", "control map rejection");
    test_btf_export_enum_synthetic();

    char x86_sha[65] = {0};
    assert(pkt_sha256_file("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o",
                           x86_sha, NULL, NULL, 0) == 0);
    test_bundle_scanner("plugins/official/pktpath-pwru-probes/bpf/x86_64/pwru_probes.bpf.o", x86_sha);
    printf("ALL WAVE 3 C UNIT TESTS PASSED!\n");
    return 0;
}
