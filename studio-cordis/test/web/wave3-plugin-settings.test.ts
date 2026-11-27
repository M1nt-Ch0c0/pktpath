import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const webDir = path.resolve(import.meta.dirname, '../../web');
function loadWave1(): any {
  const code = fs.readFileSync(path.join(webDir, 'wave1-surface.js'), 'utf8');
  const ctx: any = { window: {} };
  vm.runInNewContext(code, ctx, { filename: 'wave1-surface.js' });
  return ctx.window.PktPathWave1Surface;
}
const Wave1 = loadWave1();

const SAMPLE_PROBE_SCHEMA = {
  presets: [
    {
      id: 'egress',
      label: '发包与队列排障（默认）',
      description: '聚焦本机发包、TC 队列与进程归属',
      values: {
        probe_preset: 'egress',
        core_drop: true,
        egress_tc: true,
        sock_app: true,
        ingress_rx: false,
        l3_route: false,
        netfilter_nat: false,
        tcp_diag: false,
        drop_stack: false,
        tcp_probe: false,
      },
    },
    {
      id: 'drop-pwru',
      label: '丢包定位（pwru 模式）',
      badge: '高开销',
      description: '开启丢包调用栈、收包入口与 Netfilter/NAT',
      values: {
        probe_preset: 'drop-pwru',
        core_drop: true,
        egress_tc: false,
        sock_app: false,
        ingress_rx: true,
        l3_route: false,
        netfilter_nat: true,
        tcp_diag: false,
        drop_stack: true,
        tcp_probe: false,
      },
    },
    {
      id: 'full-path',
      label: '全链路双向（收发+路由+NAT）',
      values: {
        probe_preset: 'full-path',
        core_drop: true,
        egress_tc: true,
        sock_app: true,
        ingress_rx: true,
        l3_route: true,
        netfilter_nat: true,
        tcp_diag: false,
        drop_stack: false,
        tcp_probe: false,
      },
    },
    {
      id: 'tcp-diag',
      label: 'TCP 抖动与重传',
      values: {
        probe_preset: 'tcp-diag',
        core_drop: true,
        egress_tc: true,
        sock_app: true,
        ingress_rx: false,
        l3_route: false,
        netfilter_nat: false,
        tcp_diag: true,
        drop_stack: false,
        tcp_probe: false,
      },
    },
  ],
  groups: [
    { id: 'general', label: '常规配置', collapsible: true, defaultCollapsed: false },
    { id: 'advanced_probes', label: '高级探针分组', collapsible: true, defaultCollapsed: true },
    { id: 'empty_group', label: '空分组', collapsible: true, defaultCollapsed: true },
  ],
  fields: [
    { key: 'default_duration_sec', label: '默认采集时长（秒）', type: 'number', default: 10, group: 'general' },
    { key: 'core_drop', label: '丢包与生命周期', type: 'boolean', default: true, readOnly: true, group: 'general' },
    { key: 'egress_tc', label: '发包队列与驱动（TC/Qdisc）', type: 'boolean', default: true, group: 'general' },
    { key: 'sock_app', label: '进程与 Socket 归属', type: 'boolean', default: true, group: 'general' },
    { key: 'ingress_rx', label: '收包入口（Ingress）', type: 'boolean', default: false, badge: '高开销', group: 'advanced_probes' },
    { key: 'l3_route', label: '路由与隧道/转发', type: 'boolean', default: false, group: 'advanced_probes' },
    { key: 'netfilter_nat', label: '防火墙与 NAT', type: 'boolean', default: false, group: 'advanced_probes' },
    { key: 'tcp_diag', label: 'TCP 状态与重传', type: 'boolean', default: false, group: 'advanced_probes' },
    { key: 'drop_stack', label: '丢包内核调用栈', type: 'boolean', default: false, badge: '高开销', group: 'advanced_probes' },
    { key: 'tcp_probe', label: 'TCP 逐包 ACK 探测', type: 'boolean', default: false, badge: '高噪·易丢样', group: 'advanced_probes' },
  ],
};

test('Wave 3 ConfigSchema presets resolve active preset and auto-switch to custom on manual edit', () => {
  assert.equal(Wave1.resolveActivePreset(SAMPLE_PROBE_SCHEMA, {}), 'egress');

  const pwruCfg = Wave1.applyPresetToConfig(SAMPLE_PROBE_SCHEMA, {}, 'drop-pwru');
  assert.equal(Wave1.resolveActivePreset(SAMPLE_PROBE_SCHEMA, pwruCfg), 'drop-pwru');
  assert.equal(pwruCfg.probe_preset, 'drop-pwru');
  assert.equal(pwruCfg.core_drop, true);
  assert.equal(pwruCfg.drop_stack, true);
  assert.equal(pwruCfg.ingress_rx, true);
  assert.equal(pwruCfg.netfilter_nat, true);

  // Manual toggle immediately drops out of preset into 'custom'
  const edited = { ...pwruCfg, tcp_diag: true };
  assert.equal(Wave1.resolveActivePreset(SAMPLE_PROBE_SCHEMA, edited), 'custom');

  // Even a malformed preset cannot turn off readOnly core_drop
  const badSchema = {
    ...SAMPLE_PROBE_SCHEMA,
    presets: [{ id: 'bad', label: 'Bad', values: { core_drop: false, egress_tc: false } }],
  };
  const appliedBad = Wave1.applyPresetToConfig(badSchema, {}, 'bad');
  assert.equal(appliedBad.core_drop, true);
});

test('Wave 3 ConfigSchema groups preserve defaultCollapsed, omit empty groups, and keep ungrouped fields', () => {
  const sections = Wave1.groupSchemaFields(SAMPLE_PROBE_SCHEMA);
  assert.equal(sections.length, 2);
  assert.equal(sections[0].id, 'general');
  assert.equal(sections[0].defaultCollapsed, false);
  assert.equal(sections[0].fields.length, 4);
  assert.equal(sections[1].id, 'advanced_probes');
  assert.equal(sections[1].defaultCollapsed, true);
  assert.equal(sections[1].fields.length, 6);

  assert.equal(Wave1.isReadOnlyField(SAMPLE_PROBE_SCHEMA.fields[1]), true);
  assert.equal(Wave1.isReadOnlyField(SAMPLE_PROBE_SCHEMA.fields[2]), false);
  assert.equal(Wave1.isHighRiskBadge('高开销'), true);
  assert.equal(Wave1.isHighRiskBadge('高噪·易丢样'), true);
  assert.equal(Wave1.isHighRiskBadge('高开销/可能增加丢样'), true);
  assert.equal(Wave1.isHighRiskBadge('推荐'), false);
});

test('Wave 3 normalizeInstallPreview surfaces has_kernel_bpf, target arch objects, and hooks', () => {
  const pv = Wave1.normalizeInstallPreview({
    ok: true,
    preview: {
      id: 'pktpath.pwru-probes',
      name: 'pwru 内核网络探针包',
      has_kernel_bpf: true,
      kernel_bpf_objects: [
        { arch: 'arm64', path: 'bpf/arm64/pwru_probes.bpf.o', sha256: 'a'.repeat(64) },
        { arch: 'x86_64', path: 'bpf/x86_64/pwru_probes.bpf.o', sha256: 'b'.repeat(64) },
      ],
      kernel_probes: {
        abi_version: 1,
        hooks: [
          { id: 'ext.ingress.netif_receive_skb', group: 'ingress_rx', type: 'tracepoint', target: 'net:netif_receive_skb' },
        ],
      },
    },
  });
  assert.equal(pv.ok, true);
  assert.equal(pv.has_kernel_bpf, true);
  assert.equal(pv.kernel_bpf_objects.length, 2);
  assert.equal(pv.kernel_bpf_objects[0].arch, 'arm64');
  assert.equal(pv.kernel_bpf_hooks.length, 1);
  assert.equal(pv.kernel_bpf_hooks[0].target, 'net:netif_receive_skb');

  const safePv = Wave1.normalizeInstallPreview({
    ok: true,
    preview: { id: 'ext.csv', name: 'Plain JS Plugin' },
  });
  assert.equal(safePv.ok, true);
  assert.equal(safePv.has_kernel_bpf, false);
  assert.deepEqual(Array.from(safePv.kernel_bpf_objects), []);
});

test('Wave 3 summarizeCollectorPreset builds compact workbench summary for default, pwru, and custom configs', () => {
  const baseState = {
    collector: { default_duration_sec: 10 },
    plugins: [
      {
        id: 'builtin.collector.ebpf-tc',
        enabled: true,
        status: 'active',
        schema: SAMPLE_PROBE_SCHEMA,
        config: Wave1.applyPresetToConfig(SAMPLE_PROBE_SCHEMA, {}, 'egress'),
      },
    ],
  };
  const sDefault = Wave1.summarizeCollectorPreset(baseState);
  assert.equal(sDefault.available, true);
  assert.equal(sDefault.presetId, 'egress');
  assert.equal(sDefault.presetLabel, '发包与队列排障（默认）');
  assert.equal(sDefault.isCustom, false);
  assert.equal(sDefault.highOverhead, false);
  assert.deepEqual(Array.from(sDefault.enabledGroups), ['core_drop', 'egress_tc', 'sock_app']);

  const pwruState = {
    ...baseState,
    plugins: [
      {
        ...baseState.plugins[0],
        config: Wave1.applyPresetToConfig(SAMPLE_PROBE_SCHEMA, {}, 'drop-pwru'),
      },
    ],
  };
  const sPwru = Wave1.summarizeCollectorPreset(pwruState);
  assert.equal(sPwru.presetId, 'drop-pwru');
  assert.equal(sPwru.highOverhead, true);
  assert.ok(sPwru.enabledGroupLabels.includes('丢包内核调用栈'));

  const customState = {
    ...baseState,
    plugins: [
      {
        ...baseState.plugins[0],
        config: { ...Wave1.applyPresetToConfig(SAMPLE_PROBE_SCHEMA, {}, 'egress'), tcp_probe: true },
      },
    ],
  };
  const sCustom = Wave1.summarizeCollectorPreset(customState);
  assert.equal(sCustom.presetId, 'custom');
  assert.equal(sCustom.presetLabel, '自定义');
  assert.equal(sCustom.isCustom, true);
  assert.equal(sCustom.highOverhead, true);
});

test('Wave 3 HTML and plugin-center.js wire required BPF warning, readOnly lock, and workbench preset summary', () => {
  const html = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8');
  const pcJs = fs.readFileSync(path.join(webDir, 'plugin-center.js'), 'utf8');

  assert.match(html, /id="probePresetSummary"/);
  assert.match(pcJs, /包含将在设备内核态以 root 权限加载的 eBPF 字节码，仅安装信任来源/);
  assert.match(pcJs, /id="instBpfConfirm"/);
  assert.match(pcJs, /btnOk\.disabled = Boolean\(sig\.blocked \|\| hasBpf\)/);
  assert.match(pcJs, /必选底座/);
  assert.match(pcJs, /去插件设置调整/);
  assert.match(pcJs, /sf-preset-card/);
  assert.match(pcJs, /sf-group/);
});

test('Wave 3 describePluginSignature distinguishes trusted_key, self_declared (never official), unsigned, and invalid hard-block', () => {
  const trusted = Wave1.describePluginSignature({
    signature_status: 'verified',
    signature_trust: 'trusted_key',
    signature_key_fingerprint: 'sha256:aaaa1111',
    signature_message: 'Verified by trusted key',
  });
  assert.equal(trusted.label, '已签名校验');
  assert.equal(trusted.badgeClass, 'badge-ok');
  assert.equal(trusted.blocked, false);
  assert.equal(trusted.fingerprint, 'sha256:aaaa1111');

  const selfDecl = Wave1.describePluginSignature({
    signature_status: 'verified',
    signature_trust: 'self_declared',
    signature_key_fingerprint: 'sha256:bbbb2222',
  });
  assert.equal(selfDecl.label, '签名完整·自签非官方背书');
  assert.equal(selfDecl.badgeClass, 'badge-warn');
  assert.equal(selfDecl.blocked, false);
  assert.equal(selfDecl.fingerprint, 'sha256:bbbb2222');
  assert.doesNotMatch(selfDecl.label, /官方可信/);

  const unsigned = Wave1.describePluginSignature({
    signature_status: 'unsigned',
    signature_trust: 'none',
  });
  assert.equal(unsigned.label, '未签名');
  assert.equal(unsigned.blocked, false);

  const invalid = Wave1.describePluginSignature({
    signature_status: 'invalid',
    signature_trust: 'none',
    signature_reason: 'digest mismatch',
  });
  assert.equal(invalid.label, '签名无效·禁止安装');
  assert.equal(invalid.badgeClass, 'badge-bad');
  assert.equal(invalid.blocked, true);
  assert.match(invalid.detail, /签名校验未通过/);
});

test('Wave 3 normalizeDeviceSelfCheck reads Bo actual items/level/summary/detail schema and preserves metadata', () => {
  const rep = Wave1.normalizeDeviceSelfCheck({
    ok: true,
    serial: 'emulator-5554',
    overall: 'yellow',
    arch: 'arm64',
    kernel_release: '6.1.157-android14-g1234',
    root_mode: 'su -c',
    btf_available: false,
    agent_self_check: { status: 'degraded' },
    items: [
      { id: 'root_priv', label: 'Root / BPF 权限', level: 'green', summary: 'su -c 可用' },
      { id: 'vmlinux_btf', label: '内核 BTF', level: 'yellow', summary: '缺少 /sys/kernel/btf/vmlinux', detail: '降级为原始数值显示' },
      { id: 'core_probes', label: '核心探针', level: 'red', summary: '内核版本过低', detail: '需要 5.10+' },
    ],
  });
  assert.equal(rep.ok, true);
  assert.equal(rep.overall, 'yellow');
  assert.equal(rep.overallLabel, '可用（部分受限）');
  assert.equal(rep.sourceLabel, '设备深度检测');
  assert.equal(rep.arch, 'arm64');
  assert.equal(rep.kernel_release, '6.1.157-android14-g1234');
  assert.equal(rep.root_mode, 'su -c');
  assert.equal(rep.items.length, 3);
  assert.equal(rep.items[0].level, 'green');
  assert.equal(rep.items[0].summary, 'su -c 可用');
  assert.equal(rep.items[1].level, 'yellow');
  assert.equal(rep.items[1].detail, '降级为原始数值显示');
  assert.equal(rep.items[2].level, 'red');

  const fb = Wave1.normalizeDeviceSelfCheck({ ok: true, serial: 'dev1', overall: 'green', arch: 'x86_64', items: [] });
  assert.equal(fb.sourceLabel, '基础环境检测');
  assert.equal(fb.overallLabel, '已就绪');
});

test('Wave 3 buildFlowTcpChartsData reports disabled TCP probe honestly and never fills missing cwnd/srtt with 0', () => {
  const noProbe = Wave1.buildFlowTcpChartsData({}, [], {
    probe_inventory: [{ id: 'builtin.tcp_probe', group: 'tcp_probe', status: 'disabled_by_user' }],
  }, { proto: 'tcp', src: '10.0.0.1:1234', dst: '1.1.1.1:443' });
  assert.equal(noProbe.probeEnabled, false);
  assert.equal(noProbe.hasData, false);
  assert.match(noProbe.reason, /未开启 TCP 详细探针/);

  const withData = Wave1.buildFlowTcpChartsData({
    tcp_series: [
      { ts_ms: 1000, tcp_seq: 100, snd_cwnd: 10, srtt_us: 12000 },
      { ts_ms: 1020, tcp_seq: 1440, retransmit: true }, // missing cwnd & srtt_us must NOT become 0
      { ts_ms: 1050, tcp_seq: 2880, snd_cwnd: 8, srtt_us: 15000, dropped: true },
    ],
  }, [], {
    probe_inventory: [{ id: 'builtin.tcp_probe', group: 'tcp_probe', status: 'attached' }],
  }, {});
  assert.equal(withData.probeEnabled, true);
  assert.equal(withData.hasData, true);
  assert.equal(withData.timeSeqPoints.length, 3);
  assert.equal(withData.cwndPoints.length, 2);
  assert.equal(withData.rttPoints.length, 2);
  assert.equal(withData.retransmitCount, 1);
  assert.equal(withData.dropCount, 1);
});

test('Wave 3 extractFlowTlsEvents returns empty for default sessions and extracts matched TLS plaintext when present', () => {
  const empty = Wave1.extractFlowTlsEvents({}, {}, { pid: 100 });
  assert.equal(empty.length, 0);

  const matched = Wave1.extractFlowTlsEvents({}, {
    tls_events: [
      { ts_ns: '1732700000000000000', pid: 12345, comm: 'com.example.app', direction: 'write', library: 'boringssl', plaintext_len: 42, plaintext_preview: 'GET /health HTTP/1.1', truncated: false },
      { ts_ns: '1732700000000000100', pid: 99999, comm: 'other', direction: 'read', library: 'openssl', plaintext_len: 10, plaintext_preview: 'skip' },
    ],
  }, { pid: 12345 });
  assert.equal(matched.length, 1);
  assert.equal(matched[0].library, 'boringssl');
  assert.equal(matched[0].direction, 'write');
  assert.equal(matched[0].plaintext_preview, 'GET /health HTTP/1.1');
});

test('Wave 3 addition A HTML and JS wire flow detail TCP chart tab and hidden-by-default TLS tab', () => {
  const html = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(webDir, 'app.js'), 'utf8');
  assert.match(html, /id="drwTabTimeline"/);
  assert.match(html, /id="drwTabTcp"/);
  assert.match(html, /id="drwTabTls"[^>]*hidden/);
  assert.match(appJs, /buildFlowTcpChartsData/);
  assert.match(appJs, /extractFlowTlsEvents/);
  assert.match(appJs, /未开启 TCP 详细探针/);
});

test('Wave 3 additions B/C HTML and JS wire plugin export .zip, signature badge/block, and device self-check modal', () => {
  const html = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8');
  const pcJs = fs.readFileSync(path.join(webDir, 'plugin-center.js'), 'utf8');
  const appJs = fs.readFileSync(path.join(webDir, 'app.js'), 'utf8');

  assert.match(pcJs, /id="pcDetExport"/);
  assert.match(pcJs, /\/api\/plugins\/\$\{encodeURIComponent\(id\)\}\/export/);
  assert.match(pcJs, /instSigBadge/);
  assert.match(pcJs, /instSigBlocked/);
  assert.match(pcJs, /describePluginSignature/);
  assert.match(html, /id="btnDeviceSelfCheck"/);
  assert.match(html, /id="selfCheckModal"/);
  assert.match(appJs, /\/api\/devices\/\$\{encodeURIComponent\(serial\)\}\/self-check/);
  assert.match(appJs, /normalizeDeviceSelfCheck/);
});

test('Wave 3 UX declutter keeps technical details collapsed and avoids raw internal jargon in primary UI', () => {
  const pcJs = fs.readFileSync(path.join(webDir, 'plugin-center.js'), 'utf8');
  const appJs = fs.readFileSync(path.join(webDir, 'app.js'), 'utf8');
  assert.match(pcJs, /id="instBpfTechDetails"/);
  assert.match(pcJs, /id="instSigTechDetails"/);
  assert.match(appJs, /id="scTechDetails"/);
  assert.match(appJs, /查看技术详情/);
});
