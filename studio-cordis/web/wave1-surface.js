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
  function asPluginRecord(p) {
    if (!p || typeof p !== 'object') return p;
    if (p.meta && p.meta.id) {
      if (p.can_uninstall !== undefined) return p;
      return Object.assign({}, p, { can_uninstall: p.meta.builtin === false });
    }
    const canUninstall = p.can_uninstall !== undefined ? !!p.can_uninstall : p.builtin === false;
    return Object.assign({}, p, {
      can_uninstall: canUninstall,
      meta: {
        id: p.id,
        name: p.name,
        version: p.version,
        author: p.author,
        description: p.description,
        category: p.category,
        icon: p.icon,
        builtin: p.builtin,
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

  function normalizeInstallPreview(resp) {
    if (!resp || typeof resp !== 'object') {
      return { ok: false, error: '解析失败' };
    }
    if (resp.preview && typeof resp.preview === 'object') {
      const inner = resp.preview;
      const ok = resp.ok !== false && inner.ok !== false;
      const merged = Object.assign({}, inner, { ok });
      if (!ok && !merged.error) {
        merged.error = resp.error || '格式无效';
      }
      return merged;
    }
    if (resp.ok === true) {
      return Object.assign({}, resp, { ok: true });
    }
    return Object.assign({}, resp, { ok: false, error: resp.error || '解析失败' });
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
  };
});
