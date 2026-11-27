import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadBrowserScript } from './_load-browser-script.ts';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const surface = loadBrowserScript('../../web/wave1-surface.js');

const WAVE1 = {
  plugins: [
    { meta: { id: 'builtin.transport.android-adb' } },
    { meta: { id: 'builtin.transport.offline' } },
    { meta: { id: 'builtin.transport.linux-ssh' } },
    { meta: { id: 'builtin.collector.ebpf-tc' } },
    { meta: { id: 'builtin.collector.kernel-ext' } },
    { meta: { id: 'builtin.mode.oneshot' } },
    { meta: { id: 'builtin.analyzer.dag-reconstruct' } },
    { meta: { id: 'builtin.analyzer.anomaly-radar' } },
    { meta: { id: 'builtin.exporter.csv-report' } },
  ],
  transports: [{ kind: 'adb' }, { kind: 'ssh' }, { kind: 'offline' }],
  capture_modes: [{ mode: 'oneshot', id: 'builtin.mode.oneshot' }],
  exporters: [{ id: 'builtin.exporter.csv-report' }],
};

test('linux-ssh and kernel-ext are always stripped from plugins and transports', () => {
  const plugins = surface.visiblePlugins(WAVE1.plugins).map((p: any) => p.meta.id);
  assert.ok(!plugins.includes('builtin.transport.linux-ssh'));
  assert.ok(!plugins.includes('builtin.collector.kernel-ext'));
  assert.deepEqual(plugins, [
    'builtin.transport.android-adb',
    'builtin.transport.offline',
    'builtin.collector.ebpf-tc',
    'builtin.mode.oneshot',
    'builtin.analyzer.dag-reconstruct',
    'builtin.analyzer.anomaly-radar',
    'builtin.exporter.csv-report',
  ]);
  assert.deepEqual(surface.visibleTransports(WAVE1.transports).map((t: any) => t.kind), ['adb', 'offline']);
  assert.equal(surface.shouldShowDaemon(WAVE1), false);
  assert.equal(surface.shouldShowPcapng(WAVE1), false);
  assert.equal(surface.shouldShowRedact(WAVE1), false);
  assert.equal(surface.shouldShowTheme(WAVE1), false);
});

test('daemon, pcapng, redact and ui.theme appear only after the backend registers them', () => {
  const st = {
    plugins: [
      ...WAVE1.plugins,
      { meta: { id: 'builtin.mode.daemon' } },
      { meta: { id: 'builtin.exporter.pcapng' } },
      { meta: { id: 'builtin.exporter.redact' } },
      { meta: { id: 'builtin.ui.theme' } },
    ],
    capture_modes: [...WAVE1.capture_modes, { mode: 'daemon', id: 'builtin.mode.daemon', name: '后台蹲守' }],
    exporters: [...WAVE1.exporters, { id: 'builtin.exporter.pcapng' }, { id: 'builtin.exporter.redact' }],
  };
  assert.equal(surface.shouldShowDaemon(st), true);
  assert.equal(surface.shouldShowPcapng(st), true);
  assert.equal(surface.shouldShowRedact(st), true);
  assert.equal(surface.shouldShowTheme(st), true);
  assert.equal(surface.exporterIdFor(st, 'pcapng'), 'builtin.exporter.pcapng');
  assert.equal(surface.exporterIdFor(st, 'redact'), 'builtin.exporter.redact');
});

test('applyStaticGates never leaves ssh, kernel-ext, or unregistered gated entries visible', () => {
  const els: any = {};
  const make = (id: string, hidden = false) => { els[id] = { id, hidden, set hidden(v: boolean) { this._h = v; }, get hidden() { return this._h; }, _h: hidden }; return els[id]; };
  const theme = make('btnTheme', true);
  const pcap = make('btnExportPcap', true);
  const redact = make('btnExportRedact', true);
  const ke = make('pcKernelExtBadge', false);
  const daemonTab = { hidden: false, _h: false, set hidden(v: boolean) { this._h = v; }, get hidden() { return this._h; } };
  const uiCat = { hidden: false, _h: false, set hidden(v: boolean) { this._h = v; }, get hidden() { return this._h; } };
  const doc: any = {
    getElementById: (id: string) => {
      if (id === 'btnTheme') return theme;
      if (id === 'btnExportPcap') return pcap;
      if (id === 'drwExportPcap') return pcap;
      if (id === 'btnExportRedact') return redact;
      if (id === 'drwExportRedact') return redact;
      if (id === 'pcKernelExtBadge') return ke;
      if (id === 'paneSSH') return { hidden: false, set hidden(v: boolean) { this._h = v; }, get hidden() { return this._h; }, _h: false };
      return null;
    },
    querySelector: (sel: string) => sel.includes('daemon') ? daemonTab : sel.includes('data-cat="ui"') ? uiCat : null,
  };
  surface.applyStaticGates(doc, WAVE1);
  assert.equal(theme.hidden, true);
  assert.equal(pcap.hidden, true);
  assert.equal(redact.hidden, true);
  assert.equal(ke.hidden, true);
  assert.equal(daemonTab.hidden, true);
  assert.equal(uiCat.hidden, true);

  surface.applyStaticGates(doc, {
    plugins: [{ meta: { id: 'builtin.ui.theme' } }, { meta: { id: 'builtin.mode.daemon' } }, { meta: { id: 'builtin.exporter.pcapng' } }],
    capture_modes: [{ mode: 'daemon', id: 'builtin.mode.daemon' }],
    exporters: [{ id: 'builtin.exporter.pcapng' }],
  });
  assert.equal(theme.hidden, false);
  assert.equal(pcap.hidden, false);
  assert.equal(redact.hidden, true);
  assert.equal(daemonTab.hidden, false);
  assert.equal(uiCat.hidden, false);
});

test('Wave 1 HTML removes linux-ssh and kernel-ext entries, hides gated chrome, and drops Go-service copy', () => {
  const html = fs.readFileSync(path.join(here, '../../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(here, '../../web/app.js'), 'utf8');
  assert.doesNotMatch(html, /id="paneSSH"|id="selSSH"|data-v="ssh"|Linux SSH|id="pcKernelExtBadge"/);
  assert.match(html, /id="chkPlugins"/);
  assert.doesNotMatch(html, /真实本地 Go 服务|Go 服务已连接|不等于设备已连接|pktpath-studio\.exe/);
  assert.match(html, /本地 Cordis 服务/);
  assert.match(html, /id="btnTheme"[^>]*hidden/);
  assert.match(html, /id="btnExportPcap" hidden/);
  assert.match(html, /id="drwExportPcap" hidden/);
  assert.match(html, /id="drwExportRedact" hidden/);
  assert.match(html, /data-pane="daemon"/);
  assert.doesNotMatch(html, /data-mode="daemon"/);
  assert.match(html, /id="flowZoomToolbar"/);
  assert.match(html, /id="btnFlush"/);
  assert.match(html, /id64\.js/);
  assert.match(html, /wave1-surface\.js/);
  assert.match(html, /flow-viewport\.js/);
  assert.doesNotMatch(app, /\/api\/ssh\//);
  assert.doesNotMatch(app, /\/api\/plugins(?:\/|\b)/);
  assert.doesNotMatch(app, /\/api\/session\/export-pcapng/);
  assert.doesNotMatch(app, /\/api\/session\/redact/);
  assert.match(app, /\/api\/kernel\/export/);
  assert.match(app, /\/api\/app\/quit/);
  assert.match(app, /\/api\/health/);
  assert.match(app, /\/api\/capture\/flush/);
  assert.match(app, /data\.unsupported === true/);
  assert.match(app, /Wave1\.buildCaptureRequest/);
  assert.match(app, /Wave1\.normalizeInspectPayload/);
  assert.match(app, /parseTriggerThresholdMs/);
  assert.match(app, /default_pre_window_sec/);
  assert.doesNotMatch(app, /\/api\/session\/export-pcapng/);
  assert.doesNotMatch(app, /builtin\.transport\.linux-ssh/);
  assert.doesNotMatch(app, /builtin\.collector\.kernel-ext/);
});

test('normalizeKernelState lifts Lin Wave 1 flat plugin/transport/mode/collector shapes', () => {
  const lin = {
    version: 'cordis-wave1',
    plugin_runtime: { engine: 'cordis-node', cordis_version: '3.18.1', node_version: 'v24.22.1', in_process: true },
    plugins: [
      { id: 'builtin.transport.android-adb', name: 'Android ADB 连接', version: '1.0.0', category: 'transport', builtin: true, enabled: true, status: 'active', capabilities: ['transport.adb'], provides: ['transport.adb'], requires: [], tags: [], schema: { fields: [] }, config: {} },
      { id: 'builtin.mode.daemon', name: '常驻录制模式 (Daemon)', version: '1.0.0', category: 'collector', builtin: true, enabled: true, status: 'active', capabilities: ['capture.mode.daemon'], provides: ['capture.mode.daemon'], requires: ['collector.ebpf'], tags: ['daemon'], schema: { fields: [] }, config: { default_trigger: 'sojourn_us>50000', default_pre_window_sec: 5, default_post_window_sec: 5 } },
      { id: 'builtin.transport.linux-ssh', name: 'SSH', version: '1.0.0', category: 'transport', builtin: true, enabled: true, status: 'active' },
      { id: 'builtin.collector.kernel-ext', name: 'kernel-ext', version: '1.0.0', category: 'collector', builtin: true, enabled: true, status: 'active' },
    ],
    transports: [
      { id: 'adb', plugin_id: 'builtin.transport.android-adb', name: 'Android ADB', adb_missing: true, collector_ready: false },
      { id: 'ssh', plugin_id: 'builtin.transport.linux-ssh', name: 'Linux SSH' },
    ],
    capture_modes: [
      { id: 'oneshot', plugin_id: 'builtin.mode.oneshot', name: '短时采集 (Oneshot)' },
      { id: 'daemon', plugin_id: 'builtin.mode.daemon', name: '常驻录制 (Daemon)', supports_flush: true },
    ],
    collector: { id: 'ebpf-tc', plugin_id: 'builtin.collector.ebpf-tc', name: 'eBPF TC / Socket', default_duration_sec: 15, default_sample: 1, default_hdr_bytes: 96, scopes: ['all', 'ingress', 'egress', 'socket'] },
    exporters: [{ id: 'builtin.exporter.csv-report', name: 'CSV 报告' }, { id: 'builtin.exporter.pcapng', name: 'PCAPNG' }, { id: 'builtin.exporter.redact', name: '脱敏' }],
  };
  const st = surface.normalizeKernelState(lin);
  assert.equal(st.plugins[0].meta.id, 'builtin.transport.android-adb');
  assert.equal(st.plugins[0].enabled, true);
  assert.equal(st.transports[0].kind, 'adb');
  assert.equal(st.transports[0].short_label, 'Android ADB');
  assert.equal(st.transports[0].supports_live_capture, true);
  assert.equal(st.capture_modes[0].mode, 'oneshot');
  assert.equal(st.capture_modes[1].mode, 'daemon');
  assert.equal(st.collector.capture_hdr_bytes, 96);
  assert.deepEqual(surface.visibleTransports(st.transports).map((t: any) => t.kind), ['adb']);
  assert.ok(!surface.visiblePlugins(st.plugins).some((p: any) => surface.pluginId(p) === 'builtin.transport.linux-ssh'));
  assert.ok(!surface.visiblePlugins(st.plugins).some((p: any) => surface.pluginId(p) === 'builtin.collector.kernel-ext'));
  assert.equal(surface.shouldShowDaemon(st), true);
  assert.equal(surface.shouldShowPcapng(st), true);
  assert.equal(surface.shouldShowRedact(st), true);
  assert.equal(surface.shouldShowTheme(st), false);
  assert.deepEqual(surface.visibleDynamicExporters(st.exporters).map((e: any) => e.id), ['builtin.exporter.csv-report']);
  assert.equal(surface.exporterIdFor(st, 'pcapng'), 'builtin.exporter.pcapng');
  assert.equal(surface.exporterIdFor(st, 'redact'), 'builtin.exporter.redact');
  const again = surface.normalizeKernelState(st);
  assert.equal(again.plugins[0].meta.id, 'builtin.transport.android-adb');
});

test('sampleToNumber / parseTriggerThresholdMs / normalizeQdiscs match Lin CaptureSpec and inspect', () => {
  assert.equal(surface.sampleToNumber('1/1'), 1);
  assert.equal(surface.sampleToNumber('1/10'), 10);
  assert.equal(surface.sampleToNumber('1/100'), 100);
  assert.equal(surface.sampleToNumber(10), 10);
  assert.equal(surface.sampleToNumber(''), 1);
  assert.equal(surface.sampleToToken(1), '1/1');
  assert.equal(surface.sampleToToken(10), '1/10');
  assert.equal(surface.parseTriggerThresholdMs('sojourn_us>50000'), 50);
  assert.equal(surface.parseTriggerThresholdMs('sojourn_us>20000'), 20);
  assert.equal(surface.parseTriggerThresholdMs('20'), 20);
  const qd = surface.normalizeQdiscs(['qdisc mq 0: root', 'qdisc fq_codel 0: parent :1 limit 10240p']);
  assert.equal(qd[0].kind, 'mq');
  assert.equal(qd[0].handle, '0:');
  assert.equal(qd[1].kind, 'fq_codel');
  assert.equal(surface.normalizeQdiscs([{ kind: 'htb', handle: '1:' }])[0].kind, 'htb');
});

test('daemon stays hidden until the snapshot registers builtin.mode.daemon', () => {
  assert.equal(surface.shouldShowDaemon(WAVE1), false);
  assert.equal(surface.visibleCaptureModes(WAVE1.capture_modes, WAVE1).some((m: any) => (m.mode || m.id) === 'daemon'), false);
  const withDaemon = {
    plugins: [...WAVE1.plugins, { id: 'builtin.mode.daemon', name: 'Daemon', enabled: true, status: 'active' }],
    capture_modes: [...WAVE1.capture_modes, { id: 'daemon', plugin_id: 'builtin.mode.daemon', name: '常驻录制 (Daemon)', supports_flush: true }],
  };
  const st = surface.normalizeKernelState(withDaemon);
  assert.equal(surface.shouldShowDaemon(st), true);
  assert.deepEqual(surface.visibleCaptureModes(st.capture_modes, st).map((m: any) => m.mode), ['oneshot', 'daemon']);
});

test('disabled builtin.ui.theme hides #btnTheme while keeping the UI category tab visible for re-enabling', () => {
  const disabledState = surface.normalizeKernelState({
    plugins: [
      { id: 'builtin.ui.theme', name: '界面主题', category: 'ui', enabled: false, status: 'disabled', config: { mode: 'dark' } },
    ],
    transports: [],
    capture_modes: [],
    exporters: [],
  });
  assert.equal(surface.hasThemePlugin(disabledState), true);
  assert.equal(surface.shouldShowTheme(disabledState), false);

  const elems: Record<string, { hidden: boolean }> = {
    btnTheme: { hidden: false },
    btnExportPcap: { hidden: false },
    drwExportPcap: { hidden: false },
    btnExportRedact: { hidden: false },
    drwExportRedact: { hidden: false },
    pcKernelExtBadge: { hidden: false },
    paneSSH: { hidden: false },
  };
  const uiCat = { hidden: true };
  const doc = {
    getElementById: (id: string) => elems[id] || null,
    querySelector: (sel: string) => sel.includes('data-cat="ui"') ? uiCat : null,
  };
  surface.applyStaticGates(doc, disabledState);
  assert.equal(elems.btnTheme.hidden, true);
  assert.equal(uiCat.hidden, false);

  const activeState = surface.normalizeKernelState({
    plugins: [
      { id: 'builtin.ui.theme', name: '界面主题', category: 'ui', enabled: true, status: 'active', config: { mode: 'dark' } },
    ],
    transports: [],
    capture_modes: [],
    exporters: [],
  });
  assert.equal(surface.shouldShowTheme(activeState), true);
  surface.applyStaticGates(doc, activeState);
  assert.equal(elems.btnTheme.hidden, false);
  assert.equal(uiCat.hidden, false);
});

test('normalizeInstallPreview preserves ok=true from outer API envelope and surfaces errors cleanly', () => {
  const okWrapped = surface.normalizeInstallPreview({
    ok: true,
    preview: {
      id: 'community.analyzer.evidence-auditor',
      name: '证据完整性审计',
      version: '0.3.0',
      icon: 'search',
      capabilities: ['analyzer.evidence-auditor'],
    },
  });
  assert.equal(okWrapped.ok, true);
  assert.equal(okWrapped.id, 'community.analyzer.evidence-auditor');
  assert.equal(okWrapped.name, '证据完整性审计');

  const failedNoPreview = surface.normalizeInstallPreview({
    ok: false,
    error: '缺少 manifest.json',
  });
  assert.equal(failedNoPreview.ok, false);
  assert.equal(failedNoPreview.error, '缺少 manifest.json');

  const failedOuterWithPreview = surface.normalizeInstallPreview({
    ok: false,
    error: '签名校验失败',
    preview: { id: 'bad.plugin', name: 'Bad' },
  });
  assert.equal(failedOuterWithPreview.ok, false);
  assert.equal(failedOuterWithPreview.error, '签名校验失败');

  const failedInner = surface.normalizeInstallPreview({
    ok: true,
    preview: { ok: false, error: '版本不兼容' },
  });
  assert.equal(failedInner.ok, false);
  assert.equal(failedInner.error, '版本不兼容');

  const empty = surface.normalizeInstallPreview(null);
  assert.equal(empty.ok, false);
  assert.equal(empty.error, '解析失败');
});

test('renderPluginIcon maps Material/Lucide slugs to icons and never leaks raw ASCII slugs', () => {
  assert.equal(surface.renderPluginIcon('smartphone'), '📱');
  assert.equal(surface.renderPluginIcon('cpu'), '⚙️');
  assert.equal(surface.renderPluginIcon('play-circle'), '▶️');
  assert.equal(surface.renderPluginIcon('activity'), '📈');
  assert.equal(surface.renderPluginIcon('palette'), '🎨');
  assert.equal(surface.renderPluginIcon('📑'), '📑');
  assert.equal(surface.renderPluginIcon('🦈'), '🦈');
  assert.equal(surface.renderPluginIcon('🛡️'), '🛡️');
  assert.equal(surface.renderPluginIcon('unknown-slug-icon'), '🧩');
  assert.equal(surface.renderPluginIcon('unknown-slug-icon', '📤'), '📤');
  assert.equal(surface.renderPluginIcon('', '🧩'), '🧩');
});

test('asPluginRecord derives can_uninstall=true for external plugins when backend omits it', () => {
  const builtin = surface.asPluginRecord({ id: 'builtin.ui.theme', name: 'Theme', builtin: true });
  assert.equal(builtin.can_uninstall, false);
  const ext = surface.asPluginRecord({ id: 'community.analyzer.evidence-auditor', name: '审计', builtin: false });
  assert.equal(ext.can_uninstall, true);
  const explicitFalse = surface.asPluginRecord({ id: 'community.locked', name: 'Locked', builtin: false, can_uninstall: false });
  assert.equal(explicitFalse.can_uninstall, false);
  const wrappedExt = surface.asPluginRecord({ meta: { id: 'community.wrapped', builtin: false } });
  assert.equal(wrappedExt.can_uninstall, true);
});

test('parseTcQdiscLine extracts dev, root, and parent for tc text fallback', () => {
  const mq = surface.parseTcQdiscLine('qdisc mq 0: dev wlan0 root');
  assert.equal(mq.kind, 'mq');
  assert.equal(mq.handle, '0:');
  assert.equal(mq.dev, 'wlan0');
  assert.equal(mq.root, true);
  assert.equal(mq.parent, 'root');

  const child = surface.parseTcQdiscLine('qdisc fq_codel 0: dev wlan0 parent :1 limit 10240p flows 1024');
  assert.equal(child.kind, 'fq_codel');
  assert.equal(child.handle, '0:');
  assert.equal(child.dev, 'wlan0');
  assert.equal(child.root, false);
  assert.equal(child.parent, ':1');

  const htbChild = surface.parseTcQdiscLine('qdisc fq_codel 10: dev wlan0 parent 1:10 limit 10240p');
  assert.equal(htbChild.parent, '1:10');
  assert.equal(htbChild.root, false);

  const clsact = surface.parseTcQdiscLine('qdisc clsact ffff: dev wlan0 parent ffff:fff1');
  assert.equal(clsact.kind, 'clsact');
  assert.equal(clsact.handle, 'ffff:');
  assert.equal(clsact.parent, 'ffff:fff1');

  const noDev = surface.parseTcQdiscLine('qdisc pfifo_fast 0: root refcnt 2');
  assert.equal(noDev.dev, '');
  assert.equal(noDev.root, true);
  assert.equal(noDev.parent, 'root');
});

test('normalizeQdiscs filters multi-device tc lines by selected dev and preserves structured objects', () => {
  const lines = [
    'qdisc noqueue 0: dev lo root refcnt 2',
    'qdisc pfifo_fast 0: dev rmnet_data0 root refcnt 2',
    'qdisc mq 0: dev wlan0 root',
    'qdisc fq_codel 0: dev wlan0 parent :1 limit 10240p',
    'qdisc fq_codel 0: dev wlan0 parent :2 limit 10240p',
    'qdisc htb 1: dev eth0@if12 root r2q 10',
  ];
  const wlan = surface.normalizeQdiscs(lines, 'wlan0');
  assert.equal(wlan.length, 3);
  assert.equal(wlan[0].kind, 'mq');
  assert.equal(wlan[0].root, true);
  assert.equal(wlan[0].parent, 'root');
  assert.equal(wlan[1].parent, ':1');
  assert.equal(wlan[2].parent, ':2');

  const eth0 = surface.normalizeQdiscs(lines, 'eth0');
  assert.equal(eth0.length, 1);
  assert.equal(eth0[0].kind, 'htb');

  // Structured objects from `pktpath inspect --dev wlan0 --json` (without dev field) stay intact
  const structured = surface.normalizeQdiscs([
    { kind: 'htb', handle: '1:', root: true, packets: 42 },
    { kind: 'fq_codel', handle: '10:', parent: '1:10', packets: 12 },
  ], 'wlan0');
  assert.equal(structured.length, 2);
  assert.equal(structured[0].parent, 'root');
  assert.equal(structured[0].packets, 42);
  assert.equal(structured[1].parent, '1:10');
});

test('P0-4 & P1-11: buildCaptureRequest matches legacy Go contract in oneshot and daemon modes', () => {
  const oneshot = surface.buildCaptureRequest({
    serial: '5cc2e4eb',
    daemon: false,
    dev: 'wlan0',
    scope: 'tc-egress',
    uid: 10234,
    proto: 'tcp',
    srcIp: ' 10.0.0.2 ',
    dstIp: ' 1.1.1.1 ',
    port: '443',
    portDir: 'dst',
    mark: ' 0x10/0xff ',
    sample: '1/10',
    daemonSample: '1/100',
    sampleBy: 'flow',
    durationSec: 30,
    captureHdr: true,
    profileSendmsg: true,
    enablePlugins: true,
    allowPartial: true,
  });
  assert.equal(oneshot.mode, 'oneshot');
  assert.equal(oneshot.capture_hdr, 96);
  assert.equal('hdr_bytes' in oneshot, false);
  assert.equal('port' in oneshot, false);
  assert.equal(oneshot.src_port, 0);
  assert.equal(oneshot.dst_port, 443);
  assert.equal(oneshot.mark, '0x10/0xff');
  assert.equal(oneshot.src_ip, '10.0.0.2');
  assert.equal(oneshot.dst_ip, '1.1.1.1');
  assert.equal(oneshot.sample, '1/10');
  assert.equal(oneshot.sample_by, 'flow');
  assert.equal(oneshot.duration_sec, 30);
  assert.equal(oneshot.uid, 10234);
  assert.equal(oneshot.profile_sendmsg, true);
  assert.equal(oneshot.enable_plugins, true);
  assert.equal(oneshot.allow_partial, true);
  assert.equal(oneshot.trigger, '');
  assert.equal(oneshot.pre_window_sec, 0);
  assert.equal(oneshot.post_window_sec, 0);

  const srcPortDaemon = surface.buildCaptureRequest({
    serial: '5cc2e4eb',
    daemon: true,
    dev: 'wlan0',
    scope: 'tc-egress',
    uid: undefined,
    proto: 'udp',
    srcIp: '192.168.1.5',
    dstIp: '',
    port: '5353',
    portDir: 'src',
    mark: '0x20',
    sample: '1/1',
    daemonSample: 100,
    sampleBy: 'pkt',
    durationSec: 10,
    captureHdr: false,
    profileSendmsg: true,
    enablePlugins: false,
    allowPartial: false,
    thresholdMs: 25,
    preWindowSec: 6,
    postWindowSec: 3,
  });
  assert.equal(srcPortDaemon.mode, 'daemon');
  assert.equal(srcPortDaemon.uid, -1);
  assert.equal(srcPortDaemon.capture_hdr, 0);
  assert.equal(srcPortDaemon.src_port, 5353);
  assert.equal(srcPortDaemon.dst_port, 0);
  assert.equal(srcPortDaemon.mark, '0x20');
  assert.equal(srcPortDaemon.src_ip, '192.168.1.5');
  assert.equal(srcPortDaemon.sample, '1/100');
  assert.equal(srcPortDaemon.sample_by, 'pkt');
  assert.equal(srcPortDaemon.duration_sec, 0);
  assert.equal(srcPortDaemon.profile_sendmsg, false);
  assert.equal(srcPortDaemon.enable_plugins, false);
  assert.equal(srcPortDaemon.allow_partial, false);
  assert.equal(srcPortDaemon.trigger, 'sojourn_us>25000');
  assert.equal(srcPortDaemon.pre_window_sec, 6);
  assert.equal(srcPortDaemon.post_window_sec, 3);
});

test('P1-11: every advanced filter control in index.html is wired with zero dead controls', () => {
  const html = fs.readFileSync(path.join(here, '../../web/index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(here, '../../web/app.js'), 'utf8');
  for (const id of [
    'inpPort', 'selPortDir', 'inpSrcIp', 'inpDstIp', 'inpMark',
    'selScope', 'selSampleBy', 'chkPlugins', 'chkPartial',
    'chkCapHdr', 'chkDCapHdr', 'chkSendmsg', 'inpThreshold', 'inpPre', 'inpPost',
  ]) {
    assert.match(html, new RegExp(`id="${id}"`), `index.html missing #${id}`);
    assert.match(appJs, new RegExp(`#${id}`), `app.js does not wire #${id}`);
  }
});

test('P1-10: normalizeInspectPayload prioritizes structured inspect and blocks unattributed raw lines from leaking', () => {
  const structuredResp = {
    ok: true,
    serial: '5cc2e4eb',
    dev: 'wlan0',
    interfaces: [{ name: 'wlan0', state: 'UP', addrs: ['10.0.0.2/24'] }],
    inspect: {
      dev: 'wlan0',
      kernel_release: '6.1.157-android14-11',
      qdiscs: [{ kind: 'mq', handle: 0, parent: 0xffffffff }],
      classes: [{ kind: 'mq', handle: 1, parent: 0 }],
      adapters: [{ adapter_id: 'l2_tc_egress_core', name: 'TC/Qdisc', enabled: true, missing_reason: '' }],
    },
  };
  const norm = surface.normalizeInspectPayload(structuredResp, 'wlan0');
  assert.equal(norm.structured, true);
  assert.equal(norm.rawFallback, false);
  assert.equal(norm.unscopedRaw, false);
  assert.equal(norm.dev, 'wlan0');

  // Multi-NIC raw fallback: unattributed line without dev must NOT leak into wlan0
  const mixedLines = [
    'qdisc pfifo_fast 0: root refcnt 2',
    'qdisc noqueue 0: dev lo root refcnt 2',
    'qdisc mq 0: dev wlan0 root',
    'qdisc fq_codel 0: dev wlan0 parent :1 limit 10240p',
  ];
  const filtered = surface.normalizeQdiscs(mixedLines, 'wlan0');
  assert.equal(filtered.length, 2);
  assert.equal(filtered[0].kind, 'mq');
  assert.equal(filtered[1].kind, 'fq_codel');

  // Unscoped raw fallback (no dev on response, no dev on lines, no structured inspect)
  const rawOnlyResp = {
    ok: true,
    qdiscs: ['qdisc pfifo_fast 0: root refcnt 2'],
  };
  const rawNorm = surface.normalizeInspectPayload(rawOnlyResp, 'wlan0');
  assert.equal(rawNorm.structured, false);
  assert.equal(rawNorm.rawFallback, true);
  assert.equal(rawNorm.unscopedRaw, true);
  const rawQd = surface.normalizeQdiscs(rawNorm.inspect.qdiscs, 'wlan0', { unscopedRaw: rawNorm.unscopedRaw });
  assert.equal(rawQd.length, 0);
});

test('P2-11: demo mock inspect and device labels clearly mark simulated data', () => {
  const demoNorm = surface.normalizeInspectPayload({
    ok: true,
    dev: 'wlan0',
    is_demo: true,
    inspect: { is_demo: true, dev: 'wlan0', qdiscs: [{ kind: 'htb', handle: 0x10000, parent: 0xffffffff }] },
  }, 'wlan0');
  assert.equal(demoNorm.isDemo, true);
  assert.equal(demoNorm.inspect.is_demo, true);

  const appJs = fs.readFileSync(path.join(here, '../../web/app.js'), 'utf8');
  assert.match(appJs, /Pixel 8（模拟演示）/);
  assert.match(appJs, /模拟演示拓扑数据（非真实 Android 设备）/);
});

test('required and usedBy metadata from /api/kernel/state are preserved and locked', () => {
  const flat = surface.asPluginRecord({
    id: 'builtin.transport.offline',
    name: '离线会话存储',
    builtin: true,
    required: true,
    usedBy: ['sessions', 'session-detail', 'pull', '手机拉回'],
  });
  assert.equal(surface.isRequiredPlugin(flat), true);
  assert.equal(flat.required, true);
  assert.equal(flat.meta.required, true);
  assert.equal(flat.can_uninstall, false);
  assert.deepEqual(surface.pluginUsedByLabels(flat), ['会话列表', '会话详情', '手机拉回']);

  const snake = surface.asPluginRecord({
    meta: { id: 'builtin.analyzer.dag-reconstruct', name: '路径图重建', builtin: true },
    required: true,
    used_by: ['analysis', 'overview'],
  });
  assert.equal(surface.isRequiredPlugin(snake), true);
  assert.deepEqual(surface.pluginUsedByLabels(snake), ['路径重建与分析', '会话详情']);

  const optional = surface.asPluginRecord({
    id: 'builtin.ui.theme',
    name: '界面主题',
    builtin: true,
    required: false,
  });
  assert.equal(surface.isRequiredPlugin(optional), false);
  assert.deepEqual(surface.pluginUsedByLabels(optional), []);
});

test('formatUserError translates internal service/plugin errors and never leaks raw service is not active', () => {
  const s1 = surface.formatUserError('session.provider service is not active');
  assert.doesNotMatch(s1, /service is not active|session\.provider/i);
  assert.match(s1, /离线会话存储/);
  assert.match(s1, /插件中心/);

  const s2 = surface.formatUserError('custom.internal.svc service is not active');
  assert.doesNotMatch(s2, /service is not active|custom\.internal\.svc/i);
  assert.match(s2, /插件中心/);

  const s3 = surface.formatUserError('builtin.transport.android-adb plugin is disabled');
  assert.doesNotMatch(s3, /builtin\.transport\.android-adb|plugin is disabled/i);
  assert.match(s3, /Android ADB 连接/);

  const s4 = surface.formatUserError('builtin.mode.oneshot (or builtin.collector.ebpf-tc) plugin is disabled');
  assert.doesNotMatch(s4, /builtin\.mode\.oneshot|plugin is disabled/i);
  assert.match(s4, /复现抓包/);
  assert.match(s4, /eBPF\/TC 采集器/);

  const s5 = surface.formatUserError('required service unavailable after disabling builtin.transport.offline');
  assert.doesNotMatch(s5, /builtin\.transport\.offline|unavailable after disabling/i);
  assert.match(s5, /离线会话存储/);

  const s6 = surface.formatUserError('cannot disable required plugin builtin.transport.offline');
  assert.doesNotMatch(s6, /builtin\.transport\.offline/i);
  assert.match(s6, /核心内置底座插件，不可关闭/);

  assert.equal(surface.formatUserError('未发现 USB 设备'), '未发现 USB 设备');

  const appJs = fs.readFileSync(path.join(here, '../../web/app.js'), 'utf8');
  const pcJs = fs.readFileSync(path.join(here, '../../web/plugin-center.js'), 'utf8');
  assert.match(appJs, /Wave1\.formatUserError/);
  assert.match(pcJs, /核心内置 · 不可关闭/);
  assert.match(pcJs, /被以下核心功能依赖/);
  assert.match(pcJs, /isRequiredPlugin/);
});
