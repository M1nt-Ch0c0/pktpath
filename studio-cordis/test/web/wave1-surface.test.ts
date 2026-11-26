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
  assert.doesNotMatch(html, /id="paneSSH"|id="selSSH"|data-v="ssh"|Linux SSH|id="pcKernelExtBadge"|id="chkPlugins"/);
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
  assert.match(app, /Wave1\.sampleToNumber/);
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
