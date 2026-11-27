/* Wave 1 workbench surface gates.
 * linux-ssh and kernel-ext are never shown.
 * daemon / pcapng / redact / ui.theme appear only when the backend snapshot
 * actually registers them — no placeholder entry when they are absent.
 * CommonJS export is solely for dependency-free Node tests, not a bundle.
 */
(function (host, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else host.PktPathWave1Surface = api;
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';

  const REMOVED_PLUGIN_IDS = Object.freeze([
    'builtin.transport.linux-ssh',
    'builtin.collector.kernel-ext',
  ]);
  const REMOVED_TRANSPORT_KINDS = Object.freeze(['ssh']);
  const REMOVED_EXT_POINTS = Object.freeze(['kernel.ext']);

  const GATED = Object.freeze({
    daemon: Object.freeze(['builtin.mode.daemon', 'daemon']),
    pcapng: Object.freeze(['builtin.exporter.pcapng', 'pcapng']),
    redact: Object.freeze(['builtin.exporter.redact', 'redact']),
    theme: Object.freeze(['builtin.ui.theme']),
  });

  const removedIdSet = new Set(REMOVED_PLUGIN_IDS);
  const removedKindSet = new Set(REMOVED_TRANSPORT_KINDS);
  const removedPointSet = new Set(REMOVED_EXT_POINTS);

  function pluginId(p) {
    if (!p) return '';
    if (typeof p === 'string') return p;
    if (p.meta && p.meta.id) return String(p.meta.id);
    if (p.id) return String(p.id);
    return '';
  }

  /* Lin Wave 1 snapshot plugins are flat PluginSnapshotItem objects
   * ({id,name,...,config}), not the older {meta:{...}} wrapper. Keep both. */
  const USED_BY_LABELS = Object.freeze({
    sessions: '会话列表',
    'session-list': '会话列表',
    'session.list': '会话列表',
    'session.provider': '会话管理',
    'session-detail': '会话详情',
    'session.detail': '会话详情',
    overview: '会话详情',
    sample: '单包详情',
    pull: '手机拉回',
    'device-pull': '手机拉回',
    'capture-pull': '手机拉回',
    'adb-pull': '手机拉回',
    capture: '实时抓包',
    'live-capture': '实时抓包',
    inspect: '设备与队列检查',
    topology: '设备与队列检查',
    export: '报告与数据导出',
    exporters: '报告与数据导出',
    analysis: '路径重建与分析',
    dag: '路径重建与分析',
    reconstruct: '路径重建与分析',
  });

  const SERVICE_PLUGIN_LABELS = Object.freeze({
    'session.provider': '本地会话存储与加载',
    'builtin.transport.offline': '本地会话存储与加载',
    'transport.adb': 'Android ADB 连接',
    'builtin.transport.android-adb': 'Android ADB 连接',
    'collector.ebpf': 'eBPF/TC 采集器',
    'builtin.collector.ebpf-tc': 'eBPF/TC 采集器',
    'mode.oneshot': '复现抓包（短时）',
    'builtin.mode.oneshot': '复现抓包（短时）',
    'mode.daemon': '常驻录制（Daemon）',
    'builtin.mode.daemon': '常驻录制（Daemon）',
    'analyzer.dag': '路径图重建',
    'builtin.analyzer.dag-reconstruct': '路径图重建',
    'analyzer.anomaly': '异常雷达',
    'builtin.analyzer.anomaly-radar': '异常雷达',
    'exporter.csv': 'CSV 报告导出',
    'builtin.exporter.csv-report': 'CSV 报告导出',
    'exporter.pcapng': 'PCAPNG 导出',
    'builtin.exporter.pcapng': 'PCAPNG 导出',
    'exporter.redact': '脱敏导出',
    'builtin.exporter.redact': '脱敏导出',
    'ui.theme': '界面主题',
    'builtin.ui.theme': '界面主题',
  });

  function rawUsedBy(p) {
    if (!p || typeof p !== 'object') return [];
    const list = Array.isArray(p.usedBy)
      ? p.usedBy
      : Array.isArray(p.used_by)
        ? p.used_by
        : (p.meta && Array.isArray(p.meta.usedBy))
          ? p.meta.usedBy
          : (p.meta && Array.isArray(p.meta.used_by))
            ? p.meta.used_by
            : [];
    return list.map((x) => String(x || '').trim()).filter(Boolean);
  }

  function isRequiredPlugin(p) {
    if (!p || typeof p !== 'object') return false;
    return Boolean(p.required || (p.meta && p.meta.required));
  }

  function pluginUsedByLabels(p) {
    const seen = new Set();
    const out = [];
    for (const item of rawUsedBy(p)) {
      const key = item.toLowerCase();
      const label = Object.prototype.hasOwnProperty.call(USED_BY_LABELS, key) ? USED_BY_LABELS[key] : item;
      if (label && !seen.has(label)) {
        seen.add(label);
        out.push(label);
      }
    }
    return out;
  }

  function mapServiceOrPluginToken(token) {
    const raw = String(token || '').trim().replace(/^['"`]|['"`]$/g, '');
    if (!raw) return '';
    const lower = raw.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(SERVICE_PLUGIN_LABELS, lower)) {
      return SERVICE_PLUGIN_LABELS[lower];
    }
    return '';
  }

  function formatUserError(raw) {
    const text = String(raw == null ? '' : raw).trim();
    if (!text) return '';

    const svcInactive = /^([^\s]+)\s+service\s+is\s+not\s+active\b/i.exec(text);
    if (svcInactive) {
      const label = mapServiceOrPluginToken(svcInactive[1]);
      return label
        ? `「${label}」核心插件当前未启用，请在「插件中心」启用后再试。`
        : '所需插件功能当前未启用，请在「插件中心」检查并启用对应插件后再试。';
    }

    const pluginDisabled = /^(.+?)\s+plugin\s+is\s+disabled\b/i.exec(text);
    if (pluginDisabled) {
      const rawPart = pluginDisabled[1];
      const tokens = rawPart
        .replace(/[()]/g, ' ')
        .split(/\s+or\s+|,|、/i)
        .map((s) => s.trim())
        .filter(Boolean);
      const mapped = [];
      for (const tok of tokens) {
        const lbl = mapServiceOrPluginToken(tok);
        if (lbl && !mapped.includes(lbl)) mapped.push(lbl);
      }
      if (mapped.length) {
        return `「${mapped.join(' / ')}」插件当前已停用，请在「插件中心」启用后再试。`;
      }
      return '所需插件当前已停用，请在「插件中心」启用后再试。';
    }

    if (/^missing\s+required\s+service\(s\):/i.test(text)) {
      const rest = text.replace(/^missing\s+required\s+service\(s\):\s*/i, '');
      const labels = rest.split(',').map((s) => mapServiceOrPluginToken(s)).filter(Boolean);
      if (labels.length) {
        return `缺少前置插件「${labels.join('、')}」，请先在「插件中心」启用。`;
      }
      return '缺少所需的前置插件能力，请先在「插件中心」启用相关内置插件。';
    }

    const depUnavail = /^required\s+service\s+unavailable\s+after\s+disabling\s+(.+)$/i.exec(text);
    if (depUnavail) {
      const lbl = mapServiceOrPluginToken(depUnavail[1]);
      return lbl
        ? `前置插件「${lbl}」已停用，当前插件暂时无法运行，请先重新启用前置插件。`
        : '前置插件已停用，当前插件暂时无法运行，请先在「插件中心」重新启用前置插件。';
    }

    if (/cannot\s+disable\s+(?:required|core)\s+plugin/i.test(text)) {
      return '该插件为核心内置底座插件，不可关闭。';
    }

    if (/\bservice\s+is\s+not\s+active\b/i.test(text)) {
      return '所需插件功能当前未启用，请在「插件中心」检查并启用对应插件后再试。';
    }

    return text;
  }

  function asPluginRecord(p) {
    if (!p || typeof p !== 'object') return p;
    const required = isRequiredPlugin(p);
    const usedBy = rawUsedBy(p);
    if (p.meta && p.meta.id) {
      const canUninstall = required ? false : (p.can_uninstall !== undefined ? !!p.can_uninstall : p.meta.builtin === false);
      const nextMeta = Object.assign({}, p.meta, { required, usedBy });
      return Object.assign({}, p, { can_uninstall: canUninstall, required, usedBy, meta: nextMeta });
    }
    const canUninstall = required ? false : (p.can_uninstall !== undefined ? !!p.can_uninstall : p.builtin === false);
    return Object.assign({}, p, {
      can_uninstall: canUninstall,
      required,
      usedBy,
      meta: {
        id: p.id,
        name: p.name,
        version: p.version,
        author: p.author,
        description: p.description,
        category: p.category,
        icon: p.icon,
        builtin: p.builtin,
        required,
        usedBy,
        source_path: p.source_path,
        capabilities: p.capabilities || [],
        provides: p.provides,
        requires: p.requires,
        tags: p.tags,
      },
    });
  }

  function asTransport(t) {
    if (!t || typeof t !== 'object') return t;
    const kind = String(t.kind || t.id || '');
    const live = t.supports_live_capture != null ? !!t.supports_live_capture : kind === 'adb';
    return Object.assign({}, t, {
      kind: kind,
      short_label: t.short_label || t.name || kind,
      supports_live_capture: live,
    });
  }

  function asCaptureMode(m) {
    if (!m || typeof m !== 'object') return m;
    const mode = String(m.mode || m.id || m.kind || '');
    return Object.assign({}, m, { mode: mode, name: m.name || mode });
  }

  function asCollector(c) {
    if (!c || typeof c !== 'object') return c;
    const next = Object.assign({}, c);
    if (next.capture_hdr_bytes == null && next.default_hdr_bytes != null) {
      next.capture_hdr_bytes = next.default_hdr_bytes;
    }
    return next;
  }

  function normalizeKernelState(state) {
    if (!state || typeof state !== 'object') return state;
    return Object.assign({}, state, {
      plugins: arr(state.plugins).map(asPluginRecord),
      transports: arr(state.transports).map(asTransport),
      capture_modes: arr(state.capture_modes).map(asCaptureMode),
      collector: asCollector(state.collector || {}),
    });
  }

  /* UI sample tokens are "1/N"; Lin CaptureSpec.sample is a number N (1 = keep all). */
  function sampleToNumber(raw) {
    if (typeof raw === 'number' && isFinite(raw) && raw >= 1) return Math.floor(raw);
    const s = String(raw == null ? '' : raw).trim();
    const frac = s.match(/^1\/(\d+)$/);
    if (frac) return Math.max(1, Number(frac[1]));
    const n = Number(s);
    return isFinite(n) && n >= 1 ? Math.floor(n) : 1;
  }

  function sampleToToken(raw) {
    const n = sampleToNumber(raw);
    return n <= 1 ? '1/1' : ('1/' + n);
  }

  /* Lin daemon config uses default_trigger e.g. "sojourn_us>50000". */
  function parseTriggerThresholdMs(trigger) {
    const s = String(trigger == null ? '' : trigger).replace(/\s+/g, '');
    if (!s) return null;
    const us = s.match(/^sojourn_us>(\d+)$/i);
    if (us) return Math.max(1, Math.round(Number(us[1]) / 1000));
    const bare = s.match(/^(\d+)$/);
    if (bare) return Math.max(1, Number(bare[1]));
    return null;
  }

  function isReservedExporter(ex) {
    const id = pluginId(ex);
    return id === 'builtin.exporter.pcapng' || id === 'pcapng'
      || id === 'builtin.exporter.redact' || id === 'redact';
  }

  /* Lin inspect may return qdiscs as raw `tc qdisc show` lines or structured objects. */
  function baseIfaceName(dev) {
    return String(dev || '').trim().split('@')[0];
  }

  function parseTcQdiscLine(line) {
    const s = String(line || '').trim();
    if (!s) return null;
    const m = s.match(/^(?:qdisc\s+)?(\S+)\s+(\S+)/);
    const rest = m ? s.slice(m[0].length) : '';
    const devM = rest.match(/(?:^|\s)dev\s+(\S+)/);
    const parentM = rest.match(/(?:^|\s)parent\s+(\S+)/);
    const isRoot = !parentM && /(?:^|\s)root(?:\s|$)/.test(rest);
    const parent = parentM ? parentM[1] : (isRoot ? 'root' : '');
    return {
      kind: m ? m[1] : s,
      handle: m ? m[2] : '',
      dev: devM ? devM[1] : '',
      parent,
      root: isRoot,
      raw: s,
    };
  }

  function normalizeQdiscs(raw, dev, opts) {
    const target = baseIfaceName(dev);
    const list = arr(raw);
    const unscopedRaw = !!(opts && opts.unscopedRaw);
    const parsed = list.map((q) => {
      if (typeof q === 'string') {
        const item = parseTcQdiscLine(q);
        return item ? Object.assign(item, { _fromRawLine: true }) : null;
      }
      if (q && typeof q === 'object' && q.root === true && (q.parent === undefined || q.parent === null || q.parent === '')) {
        return Object.assign({}, q, { parent: 'root' });
      }
      return q;
    });
    const hasAttributedRawLine = parsed.some((q) => q && q._fromRawLine && q.dev);
    return parsed.filter((q) => {
      if (!q || !(q.kind || q.handle !== undefined)) return false;
      if (target && q.dev) {
        return baseIfaceName(q.dev) === target;
      }
      if (target && q._fromRawLine && !q.dev && (hasAttributedRawLine || unscopedRaw)) {
        return false;
      }
      return true;
    }).map((q) => {
      if (q && q._fromRawLine) {
        const clean = Object.assign({}, q);
        delete clean._fromRawLine;
        return clean;
      }
      return q;
    });
  }

  function normalizeInspectPayload(resp, selectedDev) {
    const d = resp && typeof resp === 'object' ? resp : {};
    const hasNested = !!(d.inspect && typeof d.inspect === 'object');
    const rawIns = hasNested
      ? Object.assign({}, d.inspect)
      : ((d.qdiscs || d.classes || d.adapters) ? Object.assign({}, d) : {});
    const qList = arr(rawIns.qdiscs);
    const hasRawStrings = qList.some((q) => typeof q === 'string');
    const hasStructuredQdiscs = qList.some((q) => q && typeof q === 'object' && (q.kind || q.handle !== undefined));
    const hasAdapters = arr(rawIns.adapters).length > 0;
    const hasClasses = arr(rawIns.classes).length > 0;
    const structured = hasNested || hasAdapters || hasClasses || hasStructuredQdiscs;
    const rawFallback = !structured && hasRawStrings;
    const explicitDev = String(rawIns.dev || d.dev || '').trim();
    const unscopedRaw = rawFallback && !explicitDev;
    const isDemo = !!(rawIns.is_demo || d.is_demo);
    const inspect = Object.assign({}, rawIns, {
      dev: explicitDev || String(selectedDev || '').trim(),
      is_demo: isDemo,
      _structured: structured,
      _rawFallback: rawFallback,
      _unscopedRaw: unscopedRaw,
    });
    return {
      inspect,
      structured,
      rawFallback,
      unscopedRaw,
      dev: inspect.dev,
      isDemo,
    };
  }

  function buildCaptureRequest(input) {
    const opts = input && typeof input === 'object' ? input : {};
    const daemon = !!opts.daemon;
    const portRaw = Number(opts.port);
    const port = Number.isFinite(portRaw) && portRaw > 0 ? Math.trunc(portRaw) : 0;
    const portDir = String(opts.portDir || 'dst').trim().toLowerCase();
    const uidRaw = opts.uid;
    const uid = (uidRaw !== '' && uidRaw !== null && uidRaw !== undefined && Number.isFinite(Number(uidRaw)))
      ? Math.trunc(Number(uidRaw))
      : -1;
    const thrRaw = Number(opts.thresholdMs);
    const thrMs = Number.isFinite(thrRaw) && thrRaw > 0 ? thrRaw : 20;
    const preRaw = Number(opts.preWindowSec);
    const postRaw = Number(opts.postWindowSec);
    const durRaw = Number(opts.durationSec);
    const durationSec = Number.isFinite(durRaw) && durRaw > 0 ? Math.trunc(durRaw) : 10;
    return {
      serial: String(opts.serial || ''),
      mode: daemon ? 'daemon' : 'oneshot',
      dev: String(opts.dev || ''),
      scope: String(opts.scope || 'tc-egress') || 'tc-egress',
      uid: uid,
      proto: String(opts.proto || ''),
      src_ip: String(opts.srcIp || '').trim(),
      dst_ip: String(opts.dstIp || '').trim(),
      src_port: port && portDir === 'src' ? port : 0,
      dst_port: port && portDir !== 'src' ? port : 0,
      mark: String(opts.mark || '').trim(),
      sample: sampleToToken(daemon ? opts.daemonSample : opts.sample),
      sample_by: String(opts.sampleBy || 'pkt') || 'pkt',
      duration_sec: daemon ? 0 : durationSec,
      capture_hdr: opts.captureHdr ? 96 : 0,
      profile_sendmsg: !daemon && !!opts.profileSendmsg,
      enable_plugins: !!opts.enablePlugins,
      allow_partial: !!opts.allowPartial,
      trigger: daemon ? `sojourn_us>${Math.round(thrMs * 1000)}` : '',
      pre_window_sec: daemon && Number.isFinite(preRaw) ? Math.max(0, Math.trunc(preRaw)) : 0,
      post_window_sec: daemon && Number.isFinite(postRaw) ? Math.max(0, Math.trunc(postRaw)) : 0,
    };
  }

  function isRemovedPlugin(p) {
    const id = pluginId(p);
    if (removedIdSet.has(id)) return true;
    const points = (p && (p.extension_points || (p.meta && p.meta.provides))) || [];
    return arr(points).some((x) => removedPointSet.has(String(x)));
  }

  function arr(x) { return Array.isArray(x) ? x : []; }

  function visiblePlugins(list) {
    return arr(list).filter((p) => !isRemovedPlugin(p));
  }

  function visibleTransports(list) {
    return arr(list).filter((t) => t && !removedKindSet.has(String(t.kind || t.id || '')) && pluginId(t) !== 'builtin.transport.linux-ssh');
  }

  function visibleCaptureModes(list, state) {
    return arr(list).filter((m) => {
      if (!m || removedIdSet.has(pluginId(m))) return false;
      const mode = String(m.mode || m.id || m.kind || '');
      if (mode === 'daemon' && state && !isRegistered(state, 'daemon')) return false;
      return true;
    });
  }

  function visibleExporters(list) {
    return arr(list).filter((ex) => ex && !removedIdSet.has(pluginId(ex)));
  }

  function visibleDynamicExporters(list) {
    return visibleExporters(list).filter((ex) => !isReservedExporter(ex));
  }

  function snapshotPlugins(state) {
    return arr(state && state.plugins);
  }

  function snapshotExporters(state) {
    return visibleExporters(state && state.exporters);
  }

  function snapshotModes(state) {
    return visibleCaptureModes(state && state.capture_modes);
  }

  function hasAnyId(items, ids) {
    const want = new Set(ids);
    return arr(items).some((item) => {
      const id = pluginId(item);
      const mode = item && (item.mode || item.kind || item.id);
      return want.has(id) || (mode && want.has(String(mode)));
    });
  }

  function isRegistered(state, feature) {
    const ids = GATED[feature];
    if (!ids) return false;
    if (hasAnyId(snapshotPlugins(state), ids)) return true;
    if (feature === 'daemon') return hasAnyId(snapshotModes(state), ids);
    if (feature === 'pcapng' || feature === 'redact') return hasAnyId(snapshotExporters(state), ids);
    return false;
  }

  function findThemePlugin(state) {
    return snapshotPlugins(state).find((p) => pluginId(p) === 'builtin.ui.theme') || null;
  }
  function hasThemePlugin(state) {
    return !!findThemePlugin(state);
  }
  function shouldShowTheme(state) {
    const rec = findThemePlugin(state);
    if (!rec) return false;
    if (rec.enabled === false) return false;
    if (rec.status === 'disabled' || rec.status === 'error') return false;
    return true;
  }
  function shouldShowDaemon(state) { return isRegistered(state, 'daemon'); }
  function shouldShowPcapng(state) { return isRegistered(state, 'pcapng'); }
  function shouldShowRedact(state) { return isRegistered(state, 'redact'); }

  function exporterIdFor(state, feature) {
    const ids = GATED[feature];
    if (!ids) return '';
    const want = new Set(ids);
    const hit = snapshotExporters(state).find((ex) => want.has(pluginId(ex)));
    return hit ? pluginId(hit) : '';
  }

  function applyStaticGates(doc, state) {
    if (!doc || typeof doc.getElementById !== 'function') return;
    const hide = (id, on) => { const el = doc.getElementById(id); if (el) el.hidden = !on; };
    hide('btnTheme', shouldShowTheme(state));
    const daemonOn = shouldShowDaemon(state);
    const daemonTab = doc.querySelector && doc.querySelector('#modeTabs [data-mode="daemon"]');
    if (daemonTab) daemonTab.hidden = !daemonOn;
    hide('btnExportPcap', shouldShowPcapng(state));
    hide('drwExportPcap', shouldShowPcapng(state));
    hide('btnExportRedact', shouldShowRedact(state));
    hide('drwExportRedact', shouldShowRedact(state));
    const ke = doc.getElementById('pcKernelExtBadge');
    if (ke) ke.hidden = true;
    const sshPane = doc.getElementById('paneSSH');
    if (sshPane) sshPane.hidden = true;
    const uiCat = doc.querySelector && doc.querySelector('#pcCatBar [data-cat="ui"]');
    if (uiCat) uiCat.hidden = !hasThemePlugin(state);
  }

  const ICON_SLUG_MAP = Object.freeze({
    smartphone: '📱',
    cpu: '⚙️',
    'play-circle': '▶️',
    activity: '📈',
    palette: '🎨',
    folder: '📂',
    'file-text': '📑',
    shield: '🛡️',
    search: '🔎',
    radar: '📡',
    network: '🕸️',
    download: '📤',
    package: '📦',
    plug: '🔌',
    settings: '⚙️',
    sliders: '🎛️',
    terminal: '💻',
    database: '🗄️',
    zap: '⚡',
    globe: '🌐',
    layers: '🧩',
    puzzle: '🧩',
  });

  function renderPluginIcon(icon, fallback) {
    const fb = fallback !== undefined ? String(fallback) : '🧩';
    const raw = String(icon || '').trim();
    if (!raw) return fb;
    const lower = raw.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(ICON_SLUG_MAP, lower)) {
      return ICON_SLUG_MAP[lower];
    }
    if (/^[a-z0-9][a-z0-9_-]*$/i.test(raw)) {
      return fb;
    }
    return raw;
  }

  const PROBE_GROUP_LABELS = Object.freeze({
    core_drop: '丢包与生命周期',
    egress_tc: '发包队列与驱动（TC/Qdisc）',
    sock_app: '进程与 Socket 归属',
    ingress_rx: '收包入口（Ingress）',
    l3_route: '路由与隧道/转发',
    netfilter_nat: '防火墙与 NAT',
    tcp_diag: 'TCP 状态与重传',
    drop_stack: '丢包内核调用栈',
    tcp_probe: 'TCP 逐包 ACK 探测',
  });

  const PROBE_PRESET_DEFS = Object.freeze({
    egress: Object.freeze({
      id: 'egress',
      label: '发包与队列排障（默认）',
      groups: Object.freeze(['core_drop', 'egress_tc', 'sock_app']),
    }),
    'drop-pwru': Object.freeze({
      id: 'drop-pwru',
      label: '丢包定位（pwru 模式）',
      groups: Object.freeze(['core_drop', 'drop_stack', 'ingress_rx', 'netfilter_nat']),
    }),
    'full-path': Object.freeze({
      id: 'full-path',
      label: '全链路双向（收发+路由+NAT）',
      groups: Object.freeze(['core_drop', 'egress_tc', 'ingress_rx', 'l3_route', 'netfilter_nat', 'sock_app']),
    }),
    'tcp-diag': Object.freeze({
      id: 'tcp-diag',
      label: 'TCP 抖动与重传',
      groups: Object.freeze(['core_drop', 'tcp_diag', 'egress_tc', 'sock_app']),
    }),
    custom: Object.freeze({
      id: 'custom',
      label: '自定义',
      groups: Object.freeze(['core_drop']),
    }),
  });

  const HIGH_OVERHEAD_GROUPS = new Set(['ingress_rx', 'drop_stack', 'tcp_probe']);

  function cloneVal(v) {
    if (v === null || typeof v !== 'object') return v;
    try { return JSON.parse(JSON.stringify(v)); } catch (_) { return v; }
  }

  function isReadOnlyField(field) {
    return Boolean(field && (field.readOnly === true || field.readonly === true));
  }

  function isHighRiskBadge(badge) {
    const s = String(badge || '').trim();
    if (!s) return false;
    return /高开销|高噪|丢样|风险|root|警告|高负载|慎用/i.test(s);
  }

  function effectiveFieldValue(field, cfg) {
    if (cfg && typeof cfg === 'object' && field && Object.prototype.hasOwnProperty.call(cfg, field.key) && cfg[field.key] !== undefined) {
      return cfg[field.key];
    }
    return field ? field.default : undefined;
  }

  function valuesMatch(a, b) {
    if (a === b) return true;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      const sa = a.map(String).sort();
      const sb = b.map(String).sort();
      for (let i = 0; i < sa.length; i++) {
        if (sa[i] !== sb[i]) return false;
      }
      return true;
    }
    if (typeof a === 'boolean' || typeof b === 'boolean') {
      return Boolean(a) === Boolean(b);
    }
    if (typeof a === 'number' && typeof b === 'number') {
      return Number.isNaN(a) && Number.isNaN(b);
    }
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      try { return JSON.stringify(a) === JSON.stringify(b); } catch (_) { return false; }
    }
    return false;
  }

  function resolveActivePreset(schema, cfg) {
    if (!schema || !Array.isArray(schema.presets) || !schema.presets.length) return '';
    const fieldMap = new Map();
    for (const f of arr(schema.fields)) {
      if (f && f.key) fieldMap.set(f.key, f);
    }
    const sourceCfg = cfg && typeof cfg === 'object' ? cfg : {};
    for (const preset of schema.presets) {
      if (!preset || !preset.id || preset.id === 'custom') continue;
      const vals = preset.values && typeof preset.values === 'object' ? preset.values : null;
      if (!vals) continue;
      const allKeys = Object.keys(vals);
      const nonMetaKeys = allKeys.filter((k) => k !== 'probe_preset' && k !== 'preset');
      const keysToCheck = nonMetaKeys.length ? nonMetaKeys : allKeys;
      if (!keysToCheck.length) continue;
      let matched = true;
      for (const k of keysToCheck) {
        const f = fieldMap.get(k);
        const cur = f ? effectiveFieldValue(f, sourceCfg) : sourceCfg[k];
        if (!valuesMatch(cur, vals[k])) {
          matched = false;
          break;
        }
      }
      if (matched) return String(preset.id);
    }
    return 'custom';
  }

  function applyPresetToConfig(schema, cfg, presetId) {
    const next = cloneVal(cfg && typeof cfg === 'object' ? cfg : {});
    const presets = arr(schema && schema.presets);
    const preset = presets.find((p) => p && String(p.id) === String(presetId));
    if (preset && preset.values && typeof preset.values === 'object') {
      for (const [k, v] of Object.entries(preset.values)) {
        next[k] = cloneVal(v);
      }
    }
    const fields = arr(schema && schema.fields);
    const hasProbePresetField = fields.some((f) => f && f.key === 'probe_preset')
      || Object.prototype.hasOwnProperty.call(next, 'probe_preset')
      || (preset && preset.values && Object.prototype.hasOwnProperty.call(preset.values, 'probe_preset'));
    const hasPresetField = fields.some((f) => f && f.key === 'preset')
      || Object.prototype.hasOwnProperty.call(next, 'preset')
      || (preset && preset.values && Object.prototype.hasOwnProperty.call(preset.values, 'preset'));
    for (const f of fields) {
      if (isReadOnlyField(f) && f.default !== undefined) {
        next[f.key] = cloneVal(f.default);
      }
    }
    const resolvedId = preset ? String(preset.id) : 'custom';
    if (hasProbePresetField) next.probe_preset = resolvedId;
    if (hasPresetField) next.preset = resolvedId;
    return next;
  }

  function groupSchemaFields(schema) {
    const fields = arr(schema && schema.fields);
    if (!fields.length) return [];
    const groups = arr(schema && schema.groups);
    if (!groups.length) {
      return [{ id: '', label: '', description: '', collapsible: false, defaultCollapsed: false, fields }];
    }
    const groupIds = new Set(groups.map((g) => g && g.id).filter(Boolean));
    const ungrouped = fields.filter((f) => !f.group || !groupIds.has(f.group));
    const sections = [];
    if (ungrouped.length) {
      sections.push({
        id: '',
        label: '',
        description: '',
        collapsible: false,
        defaultCollapsed: false,
        fields: ungrouped,
      });
    }
    for (const g of groups) {
      if (!g || !g.id) continue;
      const gFields = fields.filter((f) => f.group === g.id);
      if (!gFields.length) continue;
      sections.push({
        id: String(g.id),
        label: String(g.label || g.id),
        description: g.description ? String(g.description) : '',
        collapsible: g.collapsible !== false,
        defaultCollapsed: g.defaultCollapsed !== undefined ? Boolean(g.defaultCollapsed) : false,
        fields: gFields,
      });
    }
    return sections;
  }

  function extractProbeGroupKey(fieldKey) {
    const raw = String(fieldKey || '').trim();
    if (!raw) return '';
    if (Object.prototype.hasOwnProperty.call(PROBE_GROUP_LABELS, raw)) return raw;
    const stripped = raw.replace(/^(?:probe_group_|probe_|group_|grp_|enable_)/, '');
    if (Object.prototype.hasOwnProperty.call(PROBE_GROUP_LABELS, stripped)) return stripped;
    return '';
  }

  function summarizeCollectorPreset(state) {
    const plugins = snapshotPlugins(state);
    const colPlugin = plugins.find((p) => pluginId(p) === 'builtin.collector.ebpf-tc') || null;
    const available = Boolean(
      (state && state.collector && Object.keys(state.collector).length > 0)
      || (colPlugin && colPlugin.enabled !== false && colPlugin.status !== 'disabled')
    );
    const schema = (colPlugin && colPlugin.schema) || null;
    const cfg = (colPlugin && colPlugin.config && typeof colPlugin.config === 'object')
      ? colPlugin.config
      : ((state && state.collector && typeof state.collector === 'object') ? state.collector : {});

    let presetId = resolveActivePreset(schema, cfg);
    if (!presetId) {
      const fromCfg = cfg.probe_preset || cfg.preset || (state && state.collector && state.collector.probe_preset);
      presetId = fromCfg ? String(fromCfg) : 'egress';
    }

    const schemaPreset = arr(schema && schema.presets).find((p) => p && String(p.id) === presetId);
    const fallbackDef = Object.prototype.hasOwnProperty.call(PROBE_PRESET_DEFS, presetId)
      ? PROBE_PRESET_DEFS[presetId]
      : null;
    const presetLabel = (schemaPreset && schemaPreset.label)
      ? String(schemaPreset.label)
      : (fallbackDef ? fallbackDef.label : (presetId === 'custom' ? '自定义' : presetId));

    const enabledGroups = [];
    const seen = new Set();
    const pushGroup = (gid) => {
      const id = String(gid || '').trim();
      if (!id || seen.has(id)) return;
      seen.add(id);
      enabledGroups.push(id);
    };

    const explicitArr = Array.isArray(cfg.probe_groups)
      ? cfg.probe_groups
      : (Array.isArray(cfg.enabled_groups) ? cfg.enabled_groups : null);

    if (explicitArr) {
      pushGroup('core_drop');
      for (const g of explicitArr) pushGroup(g);
    } else {
      let foundBoolGroupField = false;
      for (const f of arr(schema && schema.fields)) {
        if (!f || f.type !== 'boolean') continue;
        const gid = extractProbeGroupKey(f.key);
        if (!gid) continue;
        foundBoolGroupField = true;
        if (Boolean(effectiveFieldValue(f, cfg))) pushGroup(gid);
      }
      if (!foundBoolGroupField) {
        for (const [k, v] of Object.entries(cfg)) {
          const gid = extractProbeGroupKey(k);
          if (!gid) continue;
          foundBoolGroupField = true;
          if (Boolean(v)) pushGroup(gid);
        }
      }
      if (foundBoolGroupField) {
        if (!seen.has('core_drop')) enabledGroups.unshift('core_drop');
      } else if (fallbackDef) {
        for (const g of fallbackDef.groups) pushGroup(g);
      } else {
        pushGroup('core_drop');
      }
    }

    const fieldLabelByGroup = new Map();
    const highOverheadLabels = [];
    for (const f of arr(schema && schema.fields)) {
      const gid = extractProbeGroupKey(f && f.key);
      if (gid && f.label) fieldLabelByGroup.set(gid, String(f.label));
      if (gid && seen.has(gid) && isHighRiskBadge(f.badge)) {
        highOverheadLabels.push(String(f.label || PROBE_GROUP_LABELS[gid] || gid));
      }
    }
    const enabledGroupLabels = enabledGroups.map((gid) =>
      PROBE_GROUP_LABELS[gid] || fieldLabelByGroup.get(gid) || gid
    );
    if (!highOverheadLabels.length) {
      for (const gid of enabledGroups) {
        if (HIGH_OVERHEAD_GROUPS.has(gid)) {
          highOverheadLabels.push(PROBE_GROUP_LABELS[gid] || gid);
        }
      }
    }

    return {
      available,
      pluginId: 'builtin.collector.ebpf-tc',
      presetId,
      presetLabel,
      isCustom: presetId === 'custom',
      enabledGroups,
      enabledGroupLabels,
      highOverhead: highOverheadLabels.length > 0,
      highOverheadLabels,
    };
  }

  function normalizeKernelBpfObjects(raw) {
    if (Array.isArray(raw)) {
      return raw.filter((x) => x && typeof x === 'object').map((x) => ({
        arch: String(x.arch || '').trim(),
        path: String(x.path || '').trim(),
        sha256: String(x.sha256 || '').trim(),
      })).filter((x) => x.arch || x.path);
    }
    if (raw && typeof raw === 'object') {
      return Object.entries(raw).map(([arch, item]) => ({
        arch: String(arch || '').trim(),
        path: String((item && item.path) || '').trim(),
        sha256: String((item && item.sha256) || '').trim(),
      })).filter((x) => x.arch || x.path);
    }
    return [];
  }

  function normalizeKernelBpfHooks(raw) {
    return arr(raw).filter((h) => h && typeof h === 'object').map((h) => ({
      id: String(h.id || '').trim(),
      group: String(h.group || '').trim(),
      sec: String(h.sec || '').trim(),
      type: String(h.type || '').trim(),
      target: String(h.target || '').trim(),
      stage: String(h.stage || '').trim(),
    }));
  }

  function enrichPreviewBpf(obj) {
    const kp = obj && obj.kernel_probes && typeof obj.kernel_probes === 'object' ? obj.kernel_probes : null;
    const objects = normalizeKernelBpfObjects(obj.kernel_bpf_objects || (kp && kp.objects));
    const hooks = normalizeKernelBpfHooks(obj.kernel_bpf_hooks || (kp && kp.hooks));
    const hasBpf = Boolean(obj.has_kernel_bpf || objects.length > 0 || hooks.length > 0);
    const rawSigStatus = String(obj.signature_status || '').trim().toLowerCase();
    const sigStatus = (rawSigStatus === 'verified' || rawSigStatus === 'invalid' || rawSigStatus === 'unsigned')
      ? rawSigStatus
      : 'unsigned';
    const rawSigTrust = String(obj.signature_trust || '').trim().toLowerCase();
    const sigTrust = (rawSigTrust === 'trusted_key' || rawSigTrust === 'self_declared' || rawSigTrust === 'none')
      ? rawSigTrust
      : (sigStatus === 'verified' ? 'self_declared' : 'none');
    const sigFp = (typeof obj.signature_key_fingerprint === 'string' && obj.signature_key_fingerprint.trim())
      ? obj.signature_key_fingerprint.trim()
      : null;
    const sigMsg = typeof obj.signature_message === 'string' ? obj.signature_message.trim() : '';
    const sigReason = typeof obj.signature_reason === 'string' ? obj.signature_reason.trim() : '';

    return Object.assign({}, obj, {
      has_kernel_bpf: hasBpf,
      kernel_bpf_objects: objects,
      kernel_bpf_hooks: hooks,
      signature_status: sigStatus,
      signature_trust: sigTrust,
      signature_key_fingerprint: sigFp,
      signature_message: sigMsg,
      signature_reason: sigReason,
    });
  }

  function describePluginSignature(pv) {
    const norm = enrichPreviewBpf(pv || {});
    const status = norm.signature_status;
    const trust = norm.signature_trust;
    const fingerprint = norm.signature_key_fingerprint;
    if (status === 'invalid') {
      return {
        status,
        trust,
        fingerprint,
        label: '签名无效·禁止安装',
        badgeClass: 'badge-bad',
        boxClass: 'is-bad',
        blocked: true,
        detail: '签名校验未通过，为保护设备安全已禁止安装。',
      };
    }
    if (status === 'verified' && trust === 'trusted_key') {
      return {
        status,
        trust,
        fingerprint,
        label: '已签名校验',
        badgeClass: 'badge-ok',
        boxClass: 'is-ok',
        blocked: false,
        detail: '已通过签名校验，可放心安装。',
      };
    }
    if (status === 'verified') {
      return {
        status,
        trust: 'self_declared',
        fingerprint,
        label: '签名完整·自签非官方背书',
        badgeClass: 'badge-warn',
        boxClass: 'is-warn',
        blocked: false,
        detail: '签名完整（自签，非官方背书），确认来源可信后再安装。',
      };
    }
    return {
      status: 'unsigned',
      trust: 'none',
      fingerprint,
      label: '未签名',
      badgeClass: 'badge-muted',
      boxClass: 'is-muted',
      blocked: false,
      detail: '未附带数字签名，仅安装你信任来源的插件。',
    };
  }

  function normalizeSelfCheckLevel(v) {
    const s = String(v || '').trim().toLowerCase();
    if (s === 'green' || s === 'ok' || s === 'pass') return 'green';
    if (s === 'red' || s === 'error' || s === 'fail' || s === 'bad') return 'red';
    return 'yellow';
  }

  function normalizeDeviceSelfCheck(resp) {
    if (!resp || typeof resp !== 'object') {
      return {
        ok: false,
        serial: '',
        overall: 'red',
        overallLabel: '自检失败',
        source: 'unknown',
        sourceLabel: '未知来源',
        arch: null,
        kernel_release: null,
        root_mode: null,
        btf_available: null,
        drop_reason_enum_count: null,
        kptr_restrict: null,
        items: [],
        checks: [],
        error: '设备自检响应无效',
      };
    }
    const overallRaw = resp.overall || (resp.status === 'ok' ? 'green' : resp.status === 'degraded' ? 'yellow' : resp.status === 'blocked' ? 'red' : '');
    const overall = normalizeSelfCheckLevel(overallRaw);
    const overallMap = { green: '已就绪', yellow: '可用（部分受限）', red: '暂不可抓包' };
    const headlineMap = {
      green: '这台设备已准备就绪，可以直接开始抓包。',
      yellow: '设备可以正常抓包，但有部分高级能力受限，不影响基础排查。',
      red: '设备目前还不能抓包，请先按下面提示处理标红项。',
    };
    const source = resp.source
      ? String(resp.source)
      : (resp.agent_self_check ? 'agent_self_check' : 'shell_fallback');
    const sourceLabel = source === 'agent_self_check'
      ? '设备深度检测'
      : source === 'shell_fallback'
        ? '基础环境检测'
        : '环境检测';
    const levelMap = { green: '通过', yellow: '降级', red: '阻塞' };
    const rawList = Array.isArray(resp.items)
      ? resp.items
      : (Array.isArray(resp.checks) ? resp.checks : []);
    const items = rawList.map((c, idx) => {
      const lv = normalizeSelfCheckLevel(c && (c.level !== undefined ? c.level : c.status));
      const summary = typeof (c && c.summary) === 'string' ? c.summary.trim() : '';
      const detail = typeof (c && c.detail) === 'string' ? c.detail.trim() : '';
      const remediation = typeof (c && c.remediation) === 'string' ? c.remediation.trim() : '';
      return {
        id: String((c && c.id) || `check_${idx + 1}`),
        label: String((c && c.label) || (c && c.id) || `检查项 ${idx + 1}`),
        level: lv,
        status: lv,
        statusLabel: levelMap[lv],
        summary,
        detail,
        remediation,
      };
    });
    return {
      ok: resp.ok !== false,
      serial: String(resp.serial || ''),
      overall,
      overallLabel: overallMap[overall],
      headline: headlineMap[overall],
      source,
      sourceLabel,
      arch: resp.arch ? String(resp.arch) : null,
      kernel_release: resp.kernel_release ? String(resp.kernel_release) : null,
      root_mode: resp.root_mode ? String(resp.root_mode) : null,
      btf_available: typeof resp.btf_available === 'boolean' ? resp.btf_available : null,
      drop_reason_enum_count: Number.isFinite(Number(resp.drop_reason_enum_count)) ? Number(resp.drop_reason_enum_count) : null,
      kptr_restrict: resp.kptr_restrict !== undefined && resp.kptr_restrict !== null ? resp.kptr_restrict : null,
      items,
      checks: items,
      error: resp.error ? String(resp.error) : '',
    };
  }

  function finiteOptNum(v) {
    if (v === null || v === undefined || v === '') return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  function isTcpDetailedProbeEnabled(sessionSummary) {
    const s = sessionSummary && typeof sessionSummary === 'object' ? sessionSummary : {};
    const inv = Array.isArray(s.probe_inventory) ? s.probe_inventory : [];
    if (inv.length) {
      return inv.some((p) =>
        p && (p.group === 'tcp_diag' || p.group === 'tcp_probe') && p.status === 'attached'
      );
    }
    const eff = Array.isArray(s.effective_groups) ? s.effective_groups
      : (Array.isArray(s.requested_groups) ? s.requested_groups : []);
    if (eff.length) {
      return eff.includes('tcp_diag') || eff.includes('tcp_probe');
    }
    const preset = String(s.probe_preset || '');
    if (preset === 'tcp-diag' || preset === 'full-path') return true;
    return false;
  }

  function sameFlowKey(a, b) {
    if (!a || !b) return false;
    if (a.flow_key && b.flow_key && String(a.flow_key) === String(b.flow_key)) return true;
    if (a.src && b.src && a.dst && b.dst) {
      const pA = String(a.proto || '').toLowerCase();
      const pB = String(b.proto || '').toLowerCase();
      return pA === pB && String(a.src) === String(b.src) && String(a.dst) === String(b.dst);
    }
    return false;
  }

  function buildFlowTcpChartsData(detail, samples, sessionSummary, row) {
    const d = detail && typeof detail === 'object' ? detail : {};
    const shanObj = (d.tcp_series && !Array.isArray(d.tcp_series) && typeof d.tcp_series === 'object') ? d.tcp_series : null;
    const probeEnabled = shanObj && typeof shanObj.tcp_probes_enabled === 'boolean'
      ? shanObj.tcp_probes_enabled
      : isTcpDetailedProbeEnabled(sessionSummary);
    const timeSeqPoints = [];
    const cwndPoints = [];
    const rttPoints = [];
    let retransmitCount = 0;
    let dropCount = 0;

    // 1. Prefer structured server-side FlowTcpSeriesResult from Shan's analyzer
    if (shanObj && (Array.isArray(shanObj.time_sequence) || Array.isArray(shanObj.cwnd_rtt))) {
      for (const pt of (Array.isArray(shanObj.time_sequence) ? shanObj.time_sequence : [])) {
        if (!pt || typeof pt !== 'object') continue;
        const tMs = finiteOptNum(pt.rel_ms) !== null ? finiteOptNum(pt.rel_ms) : timeSeqPoints.length;
        const seq = finiteOptNum(pt.rel_seq !== undefined && pt.rel_seq !== null ? pt.rel_seq : pt.seq);
        const kind = String(pt.event_kind || 'normal');
        const retransmit = kind === 'retransmit' || Boolean(pt.retransmit);
        const dropped = kind === 'drop' || Boolean(pt.dropped);
        if (retransmit) retransmitCount++;
        if (dropped) dropCount++;
        if (seq !== null) timeSeqPoints.push({ tMs, seq, retransmit, dropped });
      }
      for (const pt of (Array.isArray(shanObj.cwnd_rtt) ? shanObj.cwnd_rtt : [])) {
        if (!pt || typeof pt !== 'object') continue;
        const tMs = finiteOptNum(pt.rel_ms) !== null ? finiteOptNum(pt.rel_ms) : cwndPoints.length;
        const cwnd = finiteOptNum(pt.snd_cwnd);
        const srttUs = finiteOptNum(pt.srtt_us);
        const srttMs = finiteOptNum(pt.srtt_ms) !== null ? finiteOptNum(pt.srtt_ms) : (srttUs !== null ? srttUs / 1000 : null);
        if (cwnd !== null) cwndPoints.push({ tMs, cwnd });
        if (srttMs !== null) rttPoints.push({ tMs, srttUs: srttUs !== null ? srttUs : srttMs * 1000, rttMs: srttMs });
      }
    } else if (Array.isArray(d.tcp_series) || Array.isArray(d.time_sequence) || (d.tcp_metrics && Array.isArray(d.tcp_metrics.points))) {
      const rawSeries = Array.isArray(d.tcp_series) ? d.tcp_series
        : Array.isArray(d.time_sequence) ? d.time_sequence
        : d.tcp_metrics.points;
      let baseTs = null;
      for (const pt of rawSeries) {
        if (!pt || typeof pt !== 'object') continue;
        const tsRaw = finiteOptNum(pt.ts_ms) !== null
          ? finiteOptNum(pt.ts_ms)
          : (finiteOptNum(pt.ts_ns) !== null ? finiteOptNum(pt.ts_ns) / 1e6 : finiteOptNum(pt.rel_ms));
        if (tsRaw !== null && baseTs === null) baseTs = tsRaw;
        const tMs = tsRaw !== null ? Math.max(0, tsRaw - (baseTs || 0)) : timeSeqPoints.length;
        const seq = finiteOptNum(pt.tcp_seq !== undefined ? pt.tcp_seq : pt.seq);
        const cwnd = finiteOptNum(pt.snd_cwnd !== undefined ? pt.snd_cwnd : pt.cwnd);
        const srttUs = finiteOptNum(pt.srtt_us);
        const retransmit = Boolean(pt.retransmit || pt.is_retransmit);
        const dropped = Boolean(pt.dropped || pt.is_drop || pt.drop);
        if (retransmit) retransmitCount++;
        if (dropped) dropCount++;
        if (seq !== null) timeSeqPoints.push({ tMs, seq, retransmit, dropped });
        if (cwnd !== null) cwndPoints.push({ tMs, cwnd });
        if (srttUs !== null) rttPoints.push({ tMs, srttUs, rttMs: srttUs / 1000 });
      }
    } else {
      // 2. Collect from matching flow samples + current detail timeline (never fabricate 0 for missing fields)
      const list = [];
      const curRow = row && typeof row === 'object' ? row : {};
      if (Array.isArray(samples) && samples.length && (curRow.src || curRow.flow_key)) {
        for (const s of samples) {
          if (sameFlowKey(curRow, s)) list.push(s);
        }
      }
      if (!list.length && curRow && (curRow.tcp_seq !== undefined || curRow.snd_cwnd !== undefined || curRow.srtt_us !== undefined)) {
        list.push(curRow);
      }
      // Also inspect timeline events in detail.branches
      const brs = Array.isArray(d.branches) ? d.branches : [];
      for (const b of brs) {
        const tl = Array.isArray(b && b.timeline) ? b.timeline : [];
        for (const ev of tl) {
          if (!ev || typeof ev !== 'object') continue;
          if (ev.tcp_seq !== undefined || ev.snd_cwnd !== undefined || ev.srtt_us !== undefined) {
            list.push(ev);
          }
        }
      }
      let baseTs = null;
      for (const item of list) {
        const tsRaw = finiteOptNum(item.t_ms) !== null
          ? finiteOptNum(item.t_ms)
          : (finiteOptNum(item.ts_ns) !== null ? finiteOptNum(item.ts_ns) / 1e6 : finiteOptNum(item.rel_us) !== null ? finiteOptNum(item.rel_us) / 1000 : null);
        if (tsRaw !== null && baseTs === null) baseTs = tsRaw;
        const tMs = tsRaw !== null ? Math.max(0, tsRaw - (baseTs || 0)) : timeSeqPoints.length;
        const seq = finiteOptNum(item.tcp_seq);
        const cwnd = finiteOptNum(item.snd_cwnd);
        const srttUs = finiteOptNum(item.srtt_us);
        const stageStr = `${item.stage || ''} ${item.title || ''} ${item.outcome || ''}`.toUpperCase();
        const retransmit = Boolean(item.retransmit || /RETRANS/.test(stageStr));
        const dropped = Boolean(item.dropped || /DROP/.test(stageStr));
        if (seq !== null || cwnd !== null || srttUs !== null) {
          if (retransmit) retransmitCount++;
          if (dropped) dropCount++;
        }
        if (seq !== null) timeSeqPoints.push({ tMs, seq, retransmit, dropped });
        if (cwnd !== null) cwndPoints.push({ tMs, cwnd });
        if (srttUs !== null) rttPoints.push({ tMs, srttUs, rttMs: srttUs / 1000 });
      }
    }

    const hasData = timeSeqPoints.length > 0 || cwndPoints.length > 0 || rttPoints.length > 0;
    const reason = hasData
      ? ''
      : (shanObj && typeof shanObj.notice === 'string' && shanObj.notice.trim()
          ? shanObj.notice.trim()
          : (!probeEnabled
              ? '本次抓包未开启 TCP 详细探针，默认只记录路径和丢包，不采集拥塞窗口与往返延迟曲线。'
              : '已开启 TCP 详细探针，但这条连接本次没有采到可用于绘图的传输指标。'));

    return {
      probeEnabled,
      hasData,
      reason,
      timeSeqPoints,
      cwndPoints,
      rttPoints,
      retransmitCount,
      dropCount,
    };
  }

  function extractFlowTlsEvents(detail, sessionSummary, row) {
    const d = detail && typeof detail === 'object' ? detail : {};
    const s = sessionSummary && typeof sessionSummary === 'object' ? sessionSummary : {};
    const cur = row && typeof row === 'object' ? row : {};
    const direct = Array.isArray(d.tls_events) ? d.tls_events
      : Array.isArray(d.tls_correlation) ? d.tls_correlation
      : (d.tls_correlation && typeof d.tls_correlation === 'object' && Array.isArray(d.tls_correlation.events) ? d.tls_correlation.events : null);
    let raw = direct;
    if (!raw) {
      const sessList = Array.isArray(s.tls_events) ? s.tls_events
        : Array.isArray(s.tls_correlation) ? s.tls_correlation
        : [];
      if (sessList.length) {
        const pid = finiteOptNum(cur.pid);
        const src = String(cur.src || '');
        const dst = String(cur.dst || '');
        raw = sessList.filter((ev) => {
          if (!ev || typeof ev !== 'object') return false;
          if (pid !== null && finiteOptNum(ev.pid) === pid) return true;
          const h = ev.conn_hint && typeof ev.conn_hint === 'object' ? ev.conn_hint : null;
          if (h && src && dst) {
            const pair = `${h.src_ip || ''}:${h.src_port || ''}`;
            const peer = `${h.dst_ip || ''}:${h.dst_port || ''}`;
            if ((pair === src && peer === dst) || (pair === dst && peer === src)) return true;
          }
          return false;
        });
      } else {
        raw = [];
      }
    }
    return raw.filter((ev) => ev && typeof ev === 'object').map((ev) => ({
      ts_ns: ev.ts_ns !== undefined && ev.ts_ns !== null ? String(ev.ts_ns) : '',
      pid: finiteOptNum(ev.pid),
      tid: finiteOptNum(ev.tid),
      uid: finiteOptNum(ev.uid),
      comm: String(ev.comm || ''),
      direction: String(ev.direction || 'write').toLowerCase() === 'read' ? 'read' : 'write',
      library: String(ev.library || 'unknown'),
      conn_hint: ev.conn_hint && typeof ev.conn_hint === 'object' ? ev.conn_hint : null,
      plaintext_len: finiteOptNum(ev.plaintext_len) || 0,
      plaintext_preview: typeof ev.plaintext_preview === 'string' ? ev.plaintext_preview : '',
      truncated: Boolean(ev.truncated),
    }));
  }

  function normalizeInstallPreview(resp) {
    if (!resp || typeof resp !== 'object') {
      return { ok: false, error: '解析失败', has_kernel_bpf: false, kernel_bpf_objects: [], kernel_bpf_hooks: [] };
    }
    if (resp.preview && typeof resp.preview === 'object') {
      const inner = resp.preview;
      const ok = resp.ok !== false && inner.ok !== false;
      const merged = Object.assign({}, inner, { ok });
      if (!ok && !merged.error) {
        merged.error = resp.error || '格式无效';
      }
      return enrichPreviewBpf(merged);
    }
    if (resp.ok === true) {
      return enrichPreviewBpf(Object.assign({}, resp, { ok: true }));
    }
    return enrichPreviewBpf(Object.assign({}, resp, { ok: false, error: resp.error || '解析失败' }));
  }

  return {
    REMOVED_PLUGIN_IDS,
    REMOVED_TRANSPORT_KINDS,
    REMOVED_EXT_POINTS,
    GATED,
    pluginId,
    isRemovedPlugin,
    visiblePlugins,
    visibleTransports,
    visibleCaptureModes,
    visibleExporters,
    visibleDynamicExporters,
    isReservedExporter,
    isRegistered,
    hasThemePlugin,
    shouldShowTheme,
    shouldShowDaemon,
    shouldShowPcapng,
    shouldShowRedact,
    exporterIdFor,
    applyStaticGates,
    asPluginRecord,
    isRequiredPlugin,
    pluginUsedByLabels,
    formatUserError,
    asTransport,
    asCaptureMode,
    asCollector,
    normalizeKernelState,
    sampleToNumber,
    sampleToToken,
    parseTriggerThresholdMs,
    parseTcQdiscLine,
    normalizeQdiscs,
    normalizeInspectPayload,
    buildCaptureRequest,
    ICON_SLUG_MAP,
    renderPluginIcon,
    normalizeInstallPreview,
    PROBE_GROUP_LABELS,
    PROBE_PRESET_DEFS,
    isReadOnlyField,
    isHighRiskBadge,
    effectiveFieldValue,
    resolveActivePreset,
    applyPresetToConfig,
    groupSchemaFields,
    summarizeCollectorPreset,
    describePluginSignature,
    normalizeDeviceSelfCheck,
    isTcpDetailedProbeEnabled,
    buildFlowTcpChartsData,
    extractFlowTlsEvents,
  };
});
