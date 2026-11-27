/* PktPath Studio v2.0 — DSH/Cordis-inspired Microkernel Plugin Center,
 * Visual Schema-Form Engine (zero raw JSON), Dynamic Workbench & UI Slot Host.
 */
(function () {
  'use strict';

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const B = () => window.PktPathStudio || {};
  const Wave1 = () => window.PktPathWave1Surface || null;
  function pluginIcon(icon, fallback) {
    const w1 = Wave1();
    if (w1 && typeof w1.renderPluginIcon === 'function') return w1.renderPluginIcon(icon, fallback);
    const fb = fallback !== undefined ? String(fallback) : '🧩';
    const raw = String(icon || '').trim();
    if (!raw || /^[a-z0-9][a-z0-9_-]*$/i.test(raw)) return fb;
    return raw;
  }
  function isRequiredPlugin(p) {
    const w1 = Wave1();
    if (w1 && typeof w1.isRequiredPlugin === 'function') return w1.isRequiredPlugin(p);
    return !!(p && (p.required || (p.meta && p.meta.required)));
  }
  function usedByLabels(p) {
    const w1 = Wave1();
    if (w1 && typeof w1.pluginUsedByLabels === 'function') return w1.pluginUsedByLabels(p);
    const list = (p && (p.usedBy || p.used_by || (p.meta && (p.meta.usedBy || p.meta.used_by)))) || [];
    return Array.isArray(list) ? list.map(String).filter(Boolean) : [];
  }
  function friendlyErr(raw) {
    const w1 = Wave1();
    if (w1 && typeof w1.formatUserError === 'function') return w1.formatUserError(raw);
    return String(raw || '');
  }
  function normalizePreview(resp) {
    const w1 = Wave1();
    if (w1 && typeof w1.normalizeInstallPreview === 'function') return w1.normalizeInstallPreview(resp);
    if (resp && resp.preview && typeof resp.preview === 'object') {
      const ok = resp.ok !== false && resp.preview.ok !== false;
      return Object.assign({}, resp.preview, { ok, error: ok ? undefined : (resp.preview.error || resp.error || '格式无效') });
    }
    return resp && resp.ok ? resp : { ok: false, error: (resp && resp.error) || '解析失败' };
  }
  const esc = (s) => (B().esc ? B().esc(s) : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));

  const CAT_LABELS = {
    all: '全部',
    transport: '🔌 连接器',
    collector: '⚡ 采集与内核',
    analyzer: '📡 后分析',
    exporter: '📤 导出器',
    ui: '🎨 界面与主题',
    external: '🧩 外部扩展',
  };

  const EXT_POINT_ZH = {
    transport: '连接器',
    collector: '采集器',
    'capture.mode': '采集模式',
    'kernel.ext': '内核扩展',
    analyzer: '后分析',
    exporter: '导出器',
    'ui.slot': 'UI 插槽',
    theme: '主题',
    // kernel.ext is not a Wave 1 surface label
  };

  const ACCENTS = {
    blue:    { light: ['#2f6fed', '#1f57c9', '#e5eeff'], dark: ['#5b8cff', '#7aa2ff', '#1c2b4a'] },
    emerald: { light: ['#059669', '#047857', '#e0f7ef'], dark: ['#34d399', '#6ee7b7', '#103528'] },
    violet:  { light: ['#7c3aed', '#6d28d9', '#efe8fd'], dark: ['#a78bfa', '#c4b5fd', '#2a1f47'] },
    amber:   { light: ['#d97706', '#b45309', '#fef3c7'], dark: ['#fbbf24', '#fcd34d', '#3a2a0f'] },
    rose:    { light: ['#e11d48', '#be123c', '#ffe4e6'], dark: ['#fb7185', '#fda4af', '#3d1720'] },
  };

  const PC = {
    view: 'workbench', // 'workbench' | 'plugins'
    state: null,       // KernelSnapshot from GET /api/kernel/state
    cat: 'all',
    search: '',
    selectedId: '',
    draftCfg: {},
    pendingInstallPath: '',
    pendingPreview: null,
    loadedAssets: new Set(),
    slotRenderers: new Map(), // slotSpecId -> fn(container, ctx)
    groupOpenState: new Map(), // `${pluginId}:${groupId}` -> boolean
  };

  // Global SDK exposed to external UI slot scripts
  window.PktPathUI = {
    registerSlot(id, renderFn) {
      PC.slotRenderers.set(id, renderFn);
      mountExternalSlots();
    },
    openSample(sid) { if (B().openSample) B().openSample(sid); },
    toast(msg, kind) { if (B().toast) B().toast(msg, kind); },
    getKernelState() { return PC.state; },
    getCurrentOverview() { return B().getState ? B().getState().overview : null; },
  };

  function api(url, opts) {
    if (B().api) return B().api(url, opts);
    return fetch(url, opts).then((r) => r.json());
  }
  function toast(msg, kind, ms) {
    if (B().toast) B().toast(msg, kind, ms);
  }

  /* =====================================================================
   * 1. Main Workspace View Switcher (Workbench <-> Plugin Center)
   * ===================================================================== */
  function setMainView(view, targetPluginId) {
    PC.view = view === 'plugins' ? 'plugins' : 'workbench';
    const wb = $('#workbenchView');
    const pc = $('#pluginCenterView');
    if (wb) wb.hidden = PC.view !== 'workbench';
    if (pc) pc.hidden = PC.view !== 'plugins';
    $$('#mainNav .main-nav-tab').forEach((btn) => {
      const act = btn.dataset.view === PC.view;
      btn.classList.toggle('active', act);
      btn.setAttribute('aria-selected', act ? 'true' : 'false');
    });
    if (PC.view === 'plugins') {
      if (targetPluginId && typeof targetPluginId === 'string') {
        PC.cat = 'all';
        PC.search = '';
        const catBar = $('#pcCatBar');
        if (catBar) {
          $$('.pc-cat', catBar).forEach((x) => x.classList.toggle('active', x.dataset.cat === 'all'));
        }
        const searchEl = $('#pcSearch');
        if (searchEl) searchEl.value = '';
        PC.selectedId = targetPluginId;
        const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta && p.meta.id === targetPluginId);
        if (rec) PC.draftCfg = JSON.parse(JSON.stringify(rec.config || {}));
      }
      loadKernelState(false);
    }
  }

  /* =====================================================================
   * 2. Fetch & Apply Microkernel State Across Entire App
   * ===================================================================== */
  function setKernelState(raw) {
    let st = raw;
    if (Wave1() && Wave1().normalizeKernelState) st = Wave1().normalizeKernelState(st);
    PC.state = st;
    window.__pktpathKernelState = PC.state;
    return st;
  }

  async function loadKernelState(silent) {
    try {
      const r = await api('/api/kernel/state', { timeout: 15000 });
      if (!r || !r.state) return;
      setKernelState(r.state);
      applyKernelStateToApp(PC.state);
      if (PC.view === 'plugins') {
        renderPluginCenter();
      }
    } catch (e) {
      if (!silent) toast('读取微内核状态失败: ' + e.message, 'bad');
    }
  }

  function applyKernelStateToApp(st) {
    if (!st) return;

    // 1. Update top nav plugin count pill (Wave 1: never show kernel-ext badges)
    const visible = Wave1() ? Wave1().visiblePlugins(st.plugins || []) : (st.plugins || []);
    const activeVisible = visible.filter((p) => p.enabled || p.status === 'active').length;
    const navPill = $('#navPluginCount');
    if (navPill) navPill.textContent = `${activeVisible}/${visible.length}`;
    const pcBadge = $('#pcSummaryBadge');
    if (pcBadge) pcBadge.textContent = `${activeVisible} / ${visible.length} 已启用`;
    const keBadge = $('#pcKernelExtBadge');
    if (keBadge) keBadge.hidden = true;
    const rt = st.plugin_runtime;
    const rtBadge = $('#pcPluginRuntimeBadge');
    if (rtBadge) {
      const on = rt && (rt.in_process === true || rt.engine === 'cordis-node' || rt.enabled);
      if (on) {
        rtBadge.className = 'badge badge-ok';
        rtBadge.textContent = '默认 Cordis 插件运行时已启用';
        rtBadge.title = [rt.engine, rt.cordis_version, rt.node_version].filter(Boolean).join('\n');
      } else {
        rtBadge.className = 'badge badge-muted';
        rtBadge.textContent = '默认 Cordis 插件运行时未启用';
        rtBadge.removeAttribute('title');
      }
    }
    const inlineBadge = $('#pluginCountBadge');
    if (inlineBadge) {
      inlineBadge.textContent = `${activeVisible} 个插件运行中`;
      inlineBadge.className = 'badge badge-muted';
    }

    // 2. Theme chrome is shown only when builtin.ui.theme is active; disabling resets to default light theme.
    if (Wave1() && Wave1().shouldShowTheme(st)) {
      applyThemeSpec(st.theme || themeFromPlugin(st));
    } else {
      resetThemeSpec();
    }
    if (Wave1()) Wave1().applyStaticGates(document, st);

    // 3. Apply Collector & Capture Mode Plugin defaults (when not capturing)
    const appState = B().getState ? B().getState() : {};
    if (st.collector && !appState.capturing && B().applyCollectorDefaults) {
      B().applyCollectorDefaults(st.collector);
    }
    if (!appState.capturing && B().applyModeDefaults) {
      const oneshotP = (st.plugins || []).find((p) => (p.meta && p.meta.id) === 'builtin.mode.oneshot');
      const daemonP = (Wave1() && Wave1().shouldShowDaemon(st))
        ? (st.plugins || []).find((p) => (p.meta && p.meta.id) === 'builtin.mode.daemon')
        : null;
      B().applyModeDefaults(oneshotP && oneshotP.config, daemonP && daemonP.config);
    }

    // 4. Rebuild Dynamic Transport Tabs, Capture Mode Tabs & True Plugin-Driven Visibility
    renderDynamicTransports(st.transports || []);
    renderDynamicCaptureModes(st.capture_modes || []);
    syncWorkbenchVisibility(st);
    renderWorkbenchProbeSummary(st);

    // 5. Rebuild Dynamic Exporter Buttons from active exporter plugins
    renderDynamicExporters(st.exporters || []);

    // 6. Mount External UI Slot assets & renderers
    syncExternalUISlots(st.ui_slots || []);
  }

  function themeFromPlugin(st) {
    const w = Wave1();
    if (!w || !w.shouldShowTheme(st)) return null;
    const rec = (st.plugins || []).find((p) => w.pluginId(p) === 'builtin.ui.theme');
    return rec && rec.config ? rec.config : (st.theme || null);
  }

  function applyThemeSpec(theme) {
    if (!theme) return;
    const mode = theme.mode === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', mode);
    const pal = (ACCENTS[theme.accent] || ACCENTS.blue)[mode];
    if (pal) {
      document.documentElement.style.setProperty('--accent', pal[0]);
      document.documentElement.style.setProperty('--accent-2', pal[1]);
      document.documentElement.style.setProperty('--accent-soft', pal[2]);
    }
    document.body.classList.toggle('density-compact', theme.density === 'compact');
    const fs = Number(theme.font_scale) || 100;
    document.documentElement.style.fontSize = Math.max(85, Math.min(120, fs)) + '%';
    try { localStorage.setItem('pktpath.theme', mode); } catch (_) { /* ignore */ }
  }

  function resetThemeSpec() {
    document.documentElement.setAttribute('data-theme', 'light');
    document.documentElement.style.removeProperty('--accent');
    document.documentElement.style.removeProperty('--accent-2');
    document.documentElement.style.removeProperty('--accent-soft');
    document.documentElement.style.removeProperty('font-size');
    document.body.classList.remove('density-compact');
  }

  function renderDynamicTransports(transports) {
    const seg = $('#segTransport');
    if (!seg) return;
    const list = Wave1() ? Wave1().visibleTransports(transports) : (transports || []).filter((t) => t && t.kind !== 'ssh');
    if (!list.length) {
      seg.innerHTML = '';
      if ($('#paneADB')) $('#paneADB').hidden = true;
      if ($('#paneOffline')) $('#paneOffline').hidden = true;
      return;
    }
    const appState = B().getState ? B().getState() : { transport: 'adb' };
    const kinds = list.map((t) => t.kind);
    let cur = appState.transport === 'ssh' ? kinds[0] : appState.transport;
    if (!kinds.includes(cur)) {
      cur = kinds[0];
    }
    seg.innerHTML = list.map((t) =>
      `<button data-v="${esc(t.kind)}" class="${t.kind === cur ? 'active' : ''}" title="${esc(t.description || t.name)}">${esc(pluginIcon(t.icon, ''))} ${esc(t.short_label || t.name)}</button>`
    ).join('');
    if (B().switchTransport && cur !== appState.transport) {
      B().switchTransport(cur);
    } else {
      if ($('#paneADB')) $('#paneADB').hidden = cur !== 'adb';
      if ($('#paneOffline')) $('#paneOffline').hidden = cur !== 'offline';
    }
  }

  function renderDynamicCaptureModes(modes) {
    const tabs = $('#modeTabs');
    if (!tabs) return;
    const list = Wave1() ? Wave1().visibleCaptureModes(modes, PC.state) : (modes || []);
    if (!list.length) {
      tabs.innerHTML = '<button class="tab active" data-mode="oneshot" role="tab">复现抓包（短时）</button>';
      if (B().setCaptureMode) B().setCaptureMode('oneshot');
      return;
    }
    const appState = B().getState ? B().getState() : { mode: 'oneshot' };
    let cur = appState.mode;
    if (!list.some((m) => m.mode === cur)) {
      cur = list[0].mode;
    }
    tabs.innerHTML = list.map((m) =>
      `<button class="tab ${m.mode === cur ? 'active' : ''}" data-mode="${esc(m.mode)}" role="tab">${esc(m.name)}</button>`
    ).join('');
    if (B().setCaptureMode) {
      B().setCaptureMode(cur);
    }
  }

  // Genuine plugin-driven Workbench visibility: disabled plugins remove their controls completely.
  function syncWorkbenchVisibility(st) {
    if (!st) return;
    const transports = st.transports || [];
    const hasAnyTransport = transports.length > 0;
    const hasLiveTransport = transports.some((t) => t.supports_live_capture);
    const hasOffline = transports.some((t) => t.kind === 'offline');
    const hasCollector = !!st.collector;
    const modes = st.capture_modes || [];

    const appState = B().getState ? B().getState() : { transport: 'adb' };
    const activeTransport = transports.find((t) => t.kind === appState.transport) || transports[0] || null;
    const inLiveSource = !!(activeTransport && activeTransport.supports_live_capture);

    // Top bar device pill only when at least one live transport is active
    const devWrap = $('#appbarDeviceWrap');
    if (devWrap) devWrap.hidden = !hasLiveTransport;

    // Top bar offline buttons only when offline session plugin is active
    const btnFolder = $('#btnOpenFolder');
    if (btnFolder) btnFolder.hidden = !hasOffline;
    const histDrop = $('#historyDropdown');
    if (histDrop) histDrop.hidden = !hasOffline;

    // Left rail: empty notice vs target step
    const railEmpty = $('#railEmptyNotice');
    const stepTarget = $('#stepTarget');
    if (railEmpty) railEmpty.hidden = hasAnyTransport;
    if (stepTarget) stepTarget.hidden = !hasAnyTransport;

    // Interface & TC topology block: only when in a live transport AND eBPF collector is active
    const liveIface = $('#liveIfaceBlock');
    const colHint = $('#collectorOffHint');
    if (liveIface) liveIface.hidden = !(inLiveSource && hasCollector);
    if (colHint) colHint.hidden = !(inLiveSource && !hasCollector);

    // Step ② traffic filter: only when in live transport AND collector is active
    const stepFilter = $('#stepFilter');
    if (stepFilter) stepFilter.hidden = !(inLiveSource && hasCollector);

    // Step ③ capture modes: only when in live transport AND collector is active AND >=1 mode plugin active
    const stepMode = $('#stepCaptureMode');
    if (stepMode) stepMode.hidden = !(inLiveSource && hasCollector && modes.length > 0);

    // Empty state center copy & action buttons adapt honestly to active plugins
    const emptyDesc = $('#emptyDesc');
    const btnEmptyFolder = $('#btnEmptyOpenFolder');
    if (btnEmptyFolder) btnEmptyFolder.hidden = !hasOffline;
    if (emptyDesc) {
      if (!hasAnyTransport) {
        emptyDesc.textContent = '当前未启用任何数据源插件，请在插件中心按需开启。';
      } else if (hasLiveTransport && hasCollector && modes.length > 0) {
        emptyDesc.textContent = hasOffline
          ? '在左侧选择设备开始采集，或打开本地历史会话。'
          : '在左侧选择设备并开始采集。';
      } else if (hasOffline) {
        emptyDesc.textContent = '打开本地历史会话目录即可开始路径分析。';
      } else {
        emptyDesc.textContent = '采集器或采集模式插件已关闭，可在插件中心开启。';
      }
    }
  }

  function renderWorkbenchProbeSummary(st) {
    const box = $('#probePresetSummary');
    if (!box) return;
    const w1 = Wave1();
    const sum = w1 && typeof w1.summarizeCollectorPreset === 'function'
      ? w1.summarizeCollectorPreset(st)
      : null;
    if (!sum || !sum.available) {
      box.hidden = true;
      box.innerHTML = '';
      return;
    }
    const groupsText = sum.enabledGroupLabels.length
      ? `已启用 ${sum.enabledGroupLabels.length} 组：${sum.enabledGroupLabels.join(' · ')}`
      : '使用默认探针组合';
    const warnBadge = sum.highOverhead
      ? `<span class="badge badge-warn" title="包含高开销探针组：${esc(sum.highOverheadLabels.join('、'))}">高开销</span>`
      : '';
    box.hidden = false;
    box.innerHTML = `
      <div class="probe-summary-head">
        <span class="probe-summary-label">探针组合</span>
        <span class="badge ${sum.isCustom ? 'badge-warn' : 'badge-accent'}" id="probePresetName">${esc(sum.presetLabel)}</span>
        ${warnBadge}
        <span class="spacer"></span>
        <button type="button" class="link-btn" id="btnOpenProbeSettings" data-pid="${esc(sum.pluginId)}">去插件设置调整</button>
      </div>
      <div class="probe-summary-groups muted" title="${esc(groupsText)}">${esc(groupsText)}</div>
    `;
  }

  function renderDynamicExporters(exporters) {
    const bar = $('#dynamicExporters');
    if (!bar) return;
    const list = Wave1() ? (Wave1().visibleDynamicExporters || Wave1().visibleExporters)(exporters) : (exporters || []);
    if (!list.length) {
      bar.innerHTML = '';
      return;
    }
    bar.innerHTML = list.map((ex) =>
      `<button class="btn btn-ghost btn-sm dyn-export-btn" data-exporter="${esc(ex.id)}" title="${esc(ex.description || ex.name)}">${esc(pluginIcon(ex.icon, '📤'))} ${esc(ex.button_label || ex.name)}</button>`
    ).join('');
  }

  async function runDynamicExporter(exporterId) {
    const appState = B().getState ? B().getState() : {};
    const sessId = appState.sessionId;
    if (!sessId) {
      toast('请先打开或采集一个会话', 'warn');
      return;
    }
    const ex = ((PC.state && PC.state.exporters) || []).find((x) => x.id === exporterId);
    if (!ex) return;

    let outPath = '';
    try {
      if (ex.is_directory) {
        toast(`请选择「${ex.button_label || ex.name}」的保存目录…`);
        const r = await pickPathWithFallback('/api/dialog/pick-folder', {}, '请输入保存目录');
        if (!r || r.cancelled || !r.path) return;
        outPath = r.path;
      } else {
        const ext = ex.default_ext || '.out';
        const defName = `${ex.id}_${sessId}${ext}`;
        const r = await pickPathWithFallback('/api/dialog/save-file', { default_name: defName, filter: ex.file_filter || 'All Files (*.*)|*.*' }, '请输入保存文件路径');
        if (!r || r.cancelled || !r.path) return;
        outPath = r.path;
      }

      toast(`正在执行导出插件「${ex.name}」…`);
      const res = await api('/api/kernel/export', {
        body: { exporter_id: exporterId, session_id: sessId, out_path: outPath, params: {} },
        timeout: 180000,
      });
      if (!res || !res.ok) {
        throw new Error(friendlyErr((res && res.error) || '导出失败'));
      }
      if (B().showSavedBar) B().showSavedBar(res.out_path, `${pluginIcon(ex.icon, '✔')} ${res.summary || '已保存'}：`);
      toast(res.summary || `已保存：${res.out_path}`, 'ok', 5500);
      if (res.new_session_id && B().loadSessions) B().loadSessions();
    } catch (e) {
      if (!/cancel/i.test(String(e.message || e))) {
        toast(`导出失败：${e.message}`, 'bad');
      }
    }
  }

  /* =====================================================================
   * 3. Session Analyzer Insights & Extra KPIs + External UI Slots
   * ===================================================================== */
  function renderSessionPluginOutputs(overview) {
    const bar = $('#pluginInsightsBar');
    if (bar) {
      const insights = (overview && Array.isArray(overview.plugin_insights)) ? overview.plugin_insights : [];
      if (!insights.length) {
        bar.hidden = true;
        bar.innerHTML = '';
      } else {
        bar.hidden = false;
        bar.innerHTML = insights.map((ins) => {
          const sev = ins.severity || 'info';
          const sids = Array.isArray(ins.sample_ids) ? ins.sample_ids : [];
          const pills = sids.slice(0, 8).map((id) =>
            `<button type="button" class="ins-sample-pill" data-sid="${esc(id)}" title="点击立即打开样本 #${esc(id)} 时间线">#${esc(id)}</button>`
          ).join('');
          return `
            <div class="insight-card sev-${esc(sev)}">
              <div class="ins-head">
                <span class="ins-title">${esc(ins.title)}</span>
                ${ins.metric ? `<span class="badge ${sev === 'critical' ? 'badge-bad' : sev === 'warn' ? 'badge-warn' : sev === 'ok' ? 'badge-ok' : ''}">${esc(ins.metric)}</span>` : ''}
                <span class="spacer"></span>
                <span class="ins-src muted">${esc(ins.plugin_name || ins.plugin_id)}</span>
              </div>
              <div class="ins-body">${esc(ins.summary)}</div>
              ${pills ? `<div class="ins-samples"><span class="muted">定位样本：</span>${pills}</div>` : ''}
            </div>`;
        }).join('');
      }
    }

    // Append plugin KPIs to #kpis without duplicating
    const kpisEl = $('#kpis');
    if (kpisEl) {
      $$('.kpi-plugin', kpisEl).forEach((n) => n.remove());
      const extraKpis = (overview && Array.isArray(overview.plugin_kpis)) ? overview.plugin_kpis : [];
      for (const k of extraKpis) {
        const div = document.createElement('div');
        div.className = `kpi kpi-plugin ${k.tone || ''}`;
        div.innerHTML = `
          <div class="kpi-label">${esc(k.label)} <span class="badge badge-muted" style="font-size:10px;height:16px">插件</span></div>
          <div class="kpi-val" style="font-size:18px">${esc(k.value)}</div>
          <div class="kpi-sub">${esc(k.sub || '')}</div>`;
        kpisEl.appendChild(div);
      }
    }

    mountExternalSlots();
  }

  function syncExternalUISlots(slots) {
    const activeSet = new Set(slots.map((s) => s.id));
    // Remove unmounted slot containers whose plugin was disabled/uninstalled
    $$('[data-ext-slot-id]').forEach((el) => {
      if (!activeSet.has(el.getAttribute('data-ext-slot-id'))) {
        el.remove();
      }
    });
    for (const s of slots) {
      if (s.style_url && !PC.loadedAssets.has(s.style_url)) {
        PC.loadedAssets.add(s.style_url);
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = s.style_url;
        document.head.appendChild(link);
      }
      if (s.script_url && !PC.loadedAssets.has(s.script_url)) {
        PC.loadedAssets.add(s.script_url);
        const sc = document.createElement('script');
        sc.src = s.script_url;
        sc.async = true;
        document.head.appendChild(sc);
      }
    }
    mountExternalSlots();
  }

  function mountExternalSlots() {
    const slots = (PC.state && PC.state.ui_slots) || [];
    const overview = B().getState ? B().getState().overview : null;
    for (const s of slots) {
      const host = $(`[data-slot="${CSS.escape(s.slot)}"]`);
      if (!host) continue;
      let box = host.querySelector(`[data-ext-slot-id="${CSS.escape(s.id)}"]`);
      if (!box) {
        box = document.createElement('div');
        box.className = 'ext-slot-box';
        box.setAttribute('data-ext-slot-id', s.id);
        host.appendChild(box);
      }
      const fn = PC.slotRenderers.get(s.id);
      if (typeof fn === 'function') {
        try {
          fn(box, { slot: s, overview, kernelState: PC.state, studio: window.PktPathUI });
        } catch (err) {
          box.innerHTML = `<div class="muted" style="font-size:12px">插件 UI 插槽 ${esc(s.title)} 渲染异常: ${esc(err.message)}</div>`;
        }
      }
    }
  }

  /* =====================================================================
   * 4. Full-Page DSH-style Plugin Center & Visual Schema-Form Engine
   * ===================================================================== */
  async function pickPathWithFallback(path, body, title) {
    const r = await api(path, { body: body || {}, timeout: 0 });
    if (r && r.cancelled) return r;
    if (r && (r.unsupported || (r.ok === false && r.unsupported))) {
      const typed = typeof window.prompt === 'function' ? window.prompt(title || '请输入本机路径') : '';
      if (!typed) return { ok: false, cancelled: true, unsupported: true };
      return { ok: true, cancelled: false, path: String(typed).trim(), unsupported: true };
    }
    return r;
  }

  function filteredPlugins() {
    const raw = (PC.state && PC.state.plugins) || [];
    const list = Wave1() ? Wave1().visiblePlugins(raw) : raw.filter((p) => {
      const id = p && p.meta && p.meta.id;
      return id !== 'builtin.transport.linux-ssh' && id !== 'builtin.collector.kernel-ext';
    });
    const q = PC.search.trim().toLowerCase();
    return list.filter((p) => {
      if (PC.cat === 'external' && p.meta.builtin) return false;
      if (PC.cat !== 'all' && PC.cat !== 'external' && p.meta.category !== PC.cat) return false;
      if (!q) return true;
      const hay = [
        p.meta.id, p.meta.name, p.meta.description,
        ...(p.meta.tags || []), ...(p.meta.capabilities || []),
      ].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  function renderPluginCenter() {
    if (!PC.state) return;
    const list = filteredPlugins();
    const listEl = $('#pcList');
    if (!listEl) return;

    if (!list.length) {
      listEl.innerHTML = '<div class="empty-mini" style="padding:32px">没有匹配的插件</div>';
      $('#pcDetail').innerHTML = '<div class="empty-mini" style="padding:48px">请调整筛选条件或安装外部插件包</div>';
      return;
    }

    if (!PC.selectedId || !list.some((p) => p.meta.id === PC.selectedId)) {
      PC.selectedId = list[0].meta.id;
      PC.draftCfg = JSON.parse(JSON.stringify(list[0].config || {}));
    }

    listEl.innerHTML = list.map((p) => {
      const m = p.meta;
      const sel = m.id === PC.selectedId;
      const req = isRequiredPlugin(p);
      const deps = usedByLabels(p);
      const dotCls = p.status === 'active' ? 'dot-ok' : p.status === 'error' ? 'dot-bad' : 'dot-off';
      const originBadge = req
        ? '<span class="badge badge-accent">核心内置 · 不可关闭</span>'
        : `<span class="badge ${m.builtin ? 'badge-muted' : 'badge-violet'}">${m.builtin ? '内置' : '外部'}</span>`;
      const toggleHtml = req
        ? `<label class="switch is-locked" title="核心内置插件不可关闭" onclick="event.stopPropagation()">
              <input type="checkbox" class="pc-item-toggle" data-pid="${esc(m.id)}" checked disabled aria-disabled="true">
              <span class="switch-slider"></span>
            </label>`
        : `<label class="switch" title="${p.enabled ? '点击停用' : '点击启用'}" onclick="event.stopPropagation()">
              <input type="checkbox" class="pc-item-toggle" data-pid="${esc(m.id)}" ${p.enabled ? 'checked' : ''}>
              <span class="switch-slider"></span>
            </label>`;
      return `
        <div class="pc-item ${sel ? 'active' : ''} ${p.enabled || req ? '' : 'is-disabled'}" data-pid="${esc(m.id)}"${req ? ' data-required="1"' : ''}>
          <div class="pc-item-head">
            <span class="pc-icon">${esc(pluginIcon(m.icon, '🧩'))}</span>
            <div class="pc-item-titles">
              <div class="pc-item-name">
                <span class="pc-dot ${dotCls}"></span>
                <span>${esc(m.name)}</span>
              </div>
              <div class="pc-item-meta">
                ${originBadge}
                <span class="muted">v${esc(m.version || '1.0')}</span>
                ${(p.extension_points || []).length ? `<span class="muted">· ${p.extension_points.length} 扩展点</span>` : ''}
              </div>
            </div>
            ${toggleHtml}
          </div>
          <div class="pc-item-desc">${esc(m.description)}</div>
          ${deps.length ? `<div class="pc-item-usedby">${req ? '核心依赖：' : '依赖功能：'}${esc(deps.join(' · '))}</div>` : ''}
        </div>`;
    }).join('');

    const activePlugin = (PC.state.plugins || []).find((p) => p.meta.id === PC.selectedId);
    renderPluginDetail(activePlugin);
  }

  function renderPluginDetail(p) {
    const el = $('#pcDetail');
    if (!el || !p) return;
    const m = p.meta;
    const statusBadge = p.status === 'active'
      ? '<span class="badge badge-ok">运行中</span>'
      : p.status === 'error'
        ? '<span class="badge badge-bad">失败</span>'
        : '<span class="badge badge-muted">已停用</span>';

    const req = isRequiredPlugin(p);
    const deps = usedByLabels(p);
    const capsHtml = (m.capabilities || []).map((c) => `<li>${esc(c)}</li>`).join('') || '<li class="muted">无</li>';
    const ptsHtml = (p.extension_points || []).map((pt) => `<span class="chip chip-accent">${esc(EXT_POINT_ZH[pt] || pt)}</span>`).join('');
    const reqsHtml = (m.requires || []).map((r) => `<span class="chip">依赖 ${esc(r)}</span>`).join('');
    const usedByHtml = deps.length
      ? `<div class="pc-used-by"><span class="pc-used-by-label">${req ? '被以下核心功能依赖：' : '被以下功能依赖：'}</span><div class="pc-meta-chips">${deps.map((u) => `<span class="chip chip-accent">${esc(u)}</span>`).join('')}</div></div>`
      : (req ? '<div class="pc-used-by"><span class="pc-used-by-label">核心底座插件，不可关闭，以保障工作台基础能力正常运转。</span></div>' : '');
    const detOriginBadge = req
      ? '<span class="badge badge-accent">核心内置 · 不可关闭</span>'
      : `<span class="badge ${m.builtin ? 'badge-muted' : 'badge-violet'}">${m.builtin ? '内置' : '外部'}</span>`;
    const detToggleHtml = req
      ? `<label class="switch switch-lg is-locked" title="核心内置插件不可关闭">
            <input type="checkbox" id="pcDetToggle" data-pid="${esc(m.id)}" checked disabled aria-disabled="true">
            <span class="switch-slider"></span>
          </label>`
      : `<label class="switch switch-lg" title="${p.enabled ? '停用' : '启用'}">
            <input type="checkbox" id="pcDetToggle" data-pid="${esc(m.id)}" ${p.enabled ? 'checked' : ''}>
            <span class="switch-slider"></span>
          </label>`;

    const schemaHtml = renderSchemaForm(p.schema, PC.draftCfg, m.id);
    const hasFields = !!(p.schema && p.schema.fields && p.schema.fields.length);

    el.innerHTML = `
      <div class="pc-det-head">
        <div class="pc-det-icon">${esc(pluginIcon(m.icon, '🧩'))}</div>
        <div class="pc-det-title">
          <div class="pc-det-name-row">
            <h2>${esc(m.name)}</h2>
            ${statusBadge}
            ${detOriginBadge}
          </div>
          <div class="pc-det-sub">
            <code>${esc(m.id)}</code> · v${esc(m.version || '1.0')}
          </div>
          <p class="pc-det-desc">${esc(m.description)}</p>
        </div>
        <div class="pc-det-actions">
          ${detToggleHtml}
          <button class="btn btn-ghost btn-sm" id="pcDetExport" data-pid="${esc(m.id)}" title="将插件打包导出为 .zip">导出 .zip</button>
          <button class="btn btn-ghost btn-sm" id="pcDetReload" data-pid="${esc(m.id)}">重载</button>
          ${!req && p.can_uninstall ? `<button class="btn btn-danger btn-sm" id="pcDetUninstall" data-pid="${esc(m.id)}">卸载</button>` : ''}
        </div>
      </div>

      ${p.error ? `<div class="pc-alert-bad">${esc(friendlyErr(p.error))}</div>` : ''}

      <section class="pc-section card">
        <h3>能力</h3>
        <ul class="pc-cap-list">${capsHtml}</ul>
        ${usedByHtml}
        ${(ptsHtml || reqsHtml) ? `<div class="pc-meta-chips">${ptsHtml} ${reqsHtml}</div>` : ''}
      </section>

      <section class="pc-section card">
        <div class="pc-sec-head">
          <h3>配置</h3>
          <span class="spacer"></span>
          ${hasFields ? `
            <button class="btn btn-ghost btn-sm" id="pcBtnResetCfg" data-pid="${esc(m.id)}">恢复默认</button>
            <button class="btn btn-primary btn-sm" id="pcBtnSaveCfg" data-pid="${esc(m.id)}">保存</button>
          ` : ''}
        </div>
        <div class="schema-form" id="pcSchemaForm">${schemaHtml}</div>
      </section>
    `;
  }

  /* ---- Schemastery-style Visual Schema-Form Renderer ---- */
  function fieldVal(f, cfg) {
    const w1 = Wave1();
    if (w1 && typeof w1.effectiveFieldValue === 'function') return w1.effectiveFieldValue(f, cfg);
    return (cfg && cfg[f.key] !== undefined) ? cfg[f.key] : f.default;
  }

  function isFieldReadOnly(f) {
    const w1 = Wave1();
    if (w1 && typeof w1.isReadOnlyField === 'function') return w1.isReadOnlyField(f);
    return Boolean(f && (f.readOnly === true || f.readonly === true));
  }

  function isRiskBadge(b) {
    const w1 = Wave1();
    if (w1 && typeof w1.isHighRiskBadge === 'function') return w1.isHighRiskBadge(b);
    return /高开销|高噪|丢样|风险|root/i.test(String(b || ''));
  }

  function renderPresetsBar(schema, cfg) {
    const presets = Array.isArray(schema && schema.presets) ? schema.presets.filter((p) => p && p.id && p.id !== 'custom') : [];
    if (!presets.length) return '';
    const w1 = Wave1();
    const activeId = w1 && typeof w1.resolveActivePreset === 'function'
      ? w1.resolveActivePreset(schema, cfg)
      : 'custom';
    const activeObj = presets.find((p) => String(p.id) === activeId);
    const activeLabel = activeObj ? activeObj.label : '自定义';
    const isCustom = activeId === 'custom';
    const cardsHtml = presets.map((pr) => {
      const isAct = String(pr.id) === activeId;
      const badgeHtml = pr.badge
        ? `<span class="badge ${isRiskBadge(pr.badge) ? 'badge-warn' : 'badge-accent'} sf-preset-badge">${esc(pr.badge)}</span>`
        : '';
      return `
        <button type="button" class="sf-preset-card ${isAct ? 'active' : ''}" data-preset-id="${esc(pr.id)}" aria-pressed="${isAct ? 'true' : 'false'}">
          <div class="sf-preset-head">
            <span class="sf-preset-title">${esc(pr.label || pr.id)}</span>
            ${badgeHtml}
          </div>
          ${pr.description ? `<div class="sf-preset-desc">${esc(pr.description)}</div>` : ''}
        </button>`;
    }).join('');
    return `
      <div class="sf-presets" id="sfPresetsBar">
        <div class="sf-presets-head">
          <span class="sf-presets-title">推荐组合预设</span>
          <span class="badge ${isCustom ? 'badge-warn' : 'badge-accent'}" id="sfPresetStatus">当前：${esc(activeLabel)}</span>
        </div>
        <div class="sf-preset-grid">${cardsHtml}</div>
        <div class="sf-custom-note muted" id="sfCustomNote"${isCustom ? '' : ' hidden'}>已手动调整开关，当前处于「自定义」组合；点击上方卡片可一键恢复推荐组合。</div>
      </div>`;
  }

  function groupBoolCountText(fields, cfg) {
    const bools = (fields || []).filter((f) => f && f.type === 'boolean');
    if (!bools.length) return '';
    const on = bools.filter((f) => Boolean(fieldVal(f, cfg))).length;
    return `${on}/${bools.length} 已开启`;
  }

  function renderSchemaForm(schema, cfg, pluginId) {
    if (!schema || !Array.isArray(schema.fields) || !schema.fields.length) {
      return '<div class="empty-mini" style="padding:18px">该插件无需额外配置，启用即可自动工作。</div>';
    }
    const w1 = Wave1();
    const sections = w1 && typeof w1.groupSchemaFields === 'function'
      ? w1.groupSchemaFields(schema)
      : [{ id: '', label: '', description: '', collapsible: false, defaultCollapsed: false, fields: schema.fields }];
    const presetsHtml = renderPresetsBar(schema, cfg);
    const sectionsHtml = sections.map((sec) => {
      const fieldsHtml = sec.fields.map((f) => renderFieldControl(f, fieldVal(f, cfg), f.key)).join('');
      if (!sec.id) {
        return `<div class="sf-ungrouped">${fieldsHtml}</div>`;
      }
      const stateKey = `${pluginId || ''}:${sec.id}`;
      const isOpen = PC.groupOpenState.has(stateKey) ? PC.groupOpenState.get(stateKey) : !sec.defaultCollapsed;
      const countText = groupBoolCountText(sec.fields, cfg);
      const countHtml = countText ? `<span class="badge badge-muted sf-group-count" data-group-count="${esc(sec.id)}">${esc(countText)}</span>` : '';
      const descHtml = sec.description ? `<span class="sf-group-desc muted">${esc(sec.description)}</span>` : '';
      if (sec.collapsible) {
        return `
          <details class="sf-group" data-group-id="${esc(sec.id)}" data-plugin-id="${esc(pluginId || '')}"${isOpen ? ' open' : ''}>
            <summary class="sf-group-summary">
              <span class="sf-group-title">${esc(sec.label)}</span>
              ${countHtml}
              <span class="spacer"></span>
              ${descHtml}
            </summary>
            <div class="sf-group-body">${fieldsHtml}</div>
          </details>`;
      }
      return `
        <div class="sf-group sf-group-static" data-group-id="${esc(sec.id)}">
          <div class="sf-group-summary sf-group-summary-static">
            <span class="sf-group-title">${esc(sec.label)}</span>
            ${countHtml}
            <span class="spacer"></span>
            ${descHtml}
          </div>
          <div class="sf-group-body">${fieldsHtml}</div>
        </div>`;
    }).join('');
    return presetsHtml + sectionsHtml;
  }

  function renderFieldControl(f, val, pathKey) {
    const desc = f.description ? `<div class="sf-desc">${esc(f.description)}</div>` : '';
    const req = f.required ? '<span class="sf-req">*</span>' : '';
    const ro = isFieldReadOnly(f);
    const roBadge = ro ? '<span class="badge badge-accent sf-badge-readonly">必选底座</span>' : '';
    const fieldBadge = f.badge
      ? `<span class="badge ${isRiskBadge(f.badge) ? 'badge-warn' : 'badge-muted'} sf-field-badge">${esc(f.badge)}</span>`
      : '';
    const labelLine = `<label class="sf-label">${esc(f.label)}${req}${roBadge}${fieldBadge}</label>`;
    const roAttr = ro ? ' disabled aria-disabled="true"' : '';

    if (f.type === 'boolean') {
      return `
        <div class="sf-row sf-row-bool${ro ? ' sf-row-readonly' : ''}">
          <div class="sf-info">
            ${labelLine}
            ${desc}
          </div>
          <label class="switch${ro ? ' is-locked' : ''}"${ro ? ' title="必选底座，不可关闭"' : ''}>
            <input type="checkbox" class="sf-input" data-key="${esc(pathKey)}" data-type="boolean" ${val ? 'checked' : ''}${roAttr}>
            <span class="switch-slider"></span>
          </label>
        </div>`;
    }

    if (f.type === 'select') {
      const cur = val !== undefined && val !== null ? String(val) : String(f.default ?? '');
      const opts = (f.options || []).map((o) =>
        `<option value="${esc(o.value)}" ${String(o.value) === cur ? 'selected' : ''}>${esc(o.label || o.value)}</option>`
      ).join('');
      return `
        <div class="sf-row${ro ? ' sf-row-readonly' : ''}">
          ${labelLine}
          ${desc}
          <select class="sf-input" data-key="${esc(pathKey)}" data-type="select"${roAttr}>${opts}</select>
        </div>`;
    }

    if (f.type === 'number') {
      const numVal = val !== undefined && val !== null ? val : (f.default ?? 0);
      return `
        <div class="sf-row${ro ? ' sf-row-readonly' : ''}">
          ${labelLine}
          ${desc}
          <div class="sf-num-wrap">
            <input type="number" class="sf-input" data-key="${esc(pathKey)}" data-type="number"
              value="${esc(numVal)}"
              ${f.min !== undefined ? `min="${esc(f.min)}"` : ''}
              ${f.max !== undefined ? `max="${esc(f.max)}"` : ''}
              ${f.step !== undefined ? `step="${esc(f.step)}"` : ''}${roAttr}>
            ${f.unit ? `<span class="sf-unit">${esc(f.unit)}</span>` : ''}
          </div>
        </div>`;
    }

    if (f.type === 'file' || f.type === 'dir') {
      const strVal = val !== undefined && val !== null ? String(val) : '';
      return `
        <div class="sf-row${ro ? ' sf-row-readonly' : ''}">
          ${labelLine}
          ${desc}
          <div class="sf-path-wrap">
            <input type="text" class="sf-input" data-key="${esc(pathKey)}" data-type="string" value="${esc(strVal)}" placeholder="${esc(f.placeholder || '')}"${roAttr}>
            ${ro ? '' : `<button type="button" class="btn btn-ghost btn-sm sf-browse-btn" data-key="${esc(pathKey)}" data-browse="${esc(f.type)}" data-filter="${esc(f.file_filter || '')}">浏览…</button>`}
          </div>
        </div>`;
    }

    if (f.type === 'list') {
      const items = Array.isArray(val) ? val : [];
      const itemLabel = f.item_label || '项目';
      const cardsHtml = items.length ? items.map((item, idx) => {
        const subFields = (f.item_fields || []).map((sf) => {
          const sv = item && item[sf.key] !== undefined ? item[sf.key] : sf.default;
          return renderSubField(f.key, idx, sf, sv);
        }).join('');
        return `
          <div class="sf-list-card" data-list-key="${esc(f.key)}" data-idx="${idx}">
            <div class="sf-list-card-head">
              <span class="sf-list-card-title">${esc(itemLabel)} #${idx + 1}</span>
              <span class="spacer"></span>
              <button type="button" class="link-btn sf-list-del" data-list-key="${esc(f.key)}" data-idx="${idx}" style="color:var(--bad)">删除</button>
            </div>
            <div class="sf-list-grid">${subFields}</div>
          </div>`;
      }).join('') : `<div class="sf-list-empty muted">暂无${esc(itemLabel)}，点击下方「＋ 新增${esc(itemLabel)}」可视化添加（无需编写 JSON）</div>`;

      return `
        <div class="sf-row sf-row-list">
          <div class="sf-list-head">
            <div>
              <label class="sf-label">${esc(f.label)}${req}</label>
              ${desc}
            </div>
            <button type="button" class="btn btn-ghost btn-sm sf-list-add" data-list-key="${esc(f.key)}">＋ 新增${esc(itemLabel)}</button>
          </div>
          <div class="sf-list-items">${cardsHtml}</div>
        </div>`;
    }

    // string / path
    const strVal = val !== undefined && val !== null ? String(val) : '';
    return `
      <div class="sf-row${ro ? ' sf-row-readonly' : ''}">
        ${labelLine}
        ${desc}
        <input type="text" class="sf-input" data-key="${esc(pathKey)}" data-type="string" value="${esc(strVal)}" placeholder="${esc(f.placeholder || '')}"${roAttr}>
      </div>`;
  }

  function renderSubField(listKey, idx, sf, val) {
    const req = sf.required ? '<span class="sf-req">*</span>' : '';
    if (sf.type === 'select') {
      const cur = val !== undefined && val !== null ? String(val) : String(sf.default ?? '');
      const opts = (sf.options || []).map((o) =>
        `<option value="${esc(o.value)}" ${String(o.value) === cur ? 'selected' : ''}>${esc(o.label || o.value)}</option>`
      ).join('');
      return `<label class="sf-sub"><span class="sf-sub-lbl">${esc(sf.label)}${req}</span>
        <select class="sf-sub-input" data-list-key="${esc(listKey)}" data-idx="${idx}" data-sub-key="${esc(sf.key)}" data-type="select">${opts}</select></label>`;
    }
    if (sf.type === 'boolean') {
      return `<label class="sf-sub sf-sub-bool"><input type="checkbox" class="sf-sub-input" data-list-key="${esc(listKey)}" data-idx="${idx}" data-sub-key="${esc(sf.key)}" data-type="boolean" ${val ? 'checked' : ''}><span>${esc(sf.label)}</span></label>`;
    }
    const strVal = val !== undefined && val !== null ? String(val) : '';
    return `<label class="sf-sub"><span class="sf-sub-lbl">${esc(sf.label)}${req}</span>
      <input type="${sf.type === 'number' ? 'number' : 'text'}" class="sf-sub-input" data-list-key="${esc(listKey)}" data-idx="${idx}" data-sub-key="${esc(sf.key)}" data-type="${esc(sf.type)}" value="${esc(strVal)}" placeholder="${esc(sf.placeholder || '')}"></label>`;
  }

  function refreshSchemaLiveState(rec) {
    if (!rec || !rec.schema) return;
    const w1 = Wave1();
    const schema = rec.schema;
    if (Array.isArray(schema.presets) && schema.presets.length && w1 && typeof w1.resolveActivePreset === 'function') {
      const activeId = w1.resolveActivePreset(schema, PC.draftCfg);
      if (Object.prototype.hasOwnProperty.call(PC.draftCfg, 'probe_preset')) PC.draftCfg.probe_preset = activeId;
      if (Object.prototype.hasOwnProperty.call(PC.draftCfg, 'preset')) PC.draftCfg.preset = activeId;
      const activeObj = schema.presets.find((p) => p && String(p.id) === activeId);
      const activeLabel = activeObj ? activeObj.label : '自定义';
      const isCustom = activeId === 'custom';
      $$('#sfPresetsBar .sf-preset-card').forEach((card) => {
        const hit = card.dataset.presetId === activeId;
        card.classList.toggle('active', hit);
        card.setAttribute('aria-pressed', hit ? 'true' : 'false');
      });
      const stEl = $('#sfPresetStatus');
      if (stEl) {
        stEl.textContent = `当前：${activeLabel}`;
        stEl.className = `badge ${isCustom ? 'badge-warn' : 'badge-accent'}`;
      }
      const noteEl = $('#sfCustomNote');
      if (noteEl) noteEl.hidden = !isCustom;
    }
    if (w1 && typeof w1.groupSchemaFields === 'function') {
      for (const sec of w1.groupSchemaFields(schema)) {
        if (!sec.id) continue;
        const cntEl = $(`[data-group-count="${CSS.escape(sec.id)}"]`);
        if (cntEl) cntEl.textContent = groupBoolCountText(sec.fields, PC.draftCfg);
      }
    }
  }

  function syncDraftFromEvent(target) {
    if (target.disabled) return;
    if (target.classList.contains('sf-input')) {
      const key = target.dataset.key;
      const typ = target.dataset.type;
      const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta && p.meta.id === PC.selectedId);
      const field = rec && rec.schema && (rec.schema.fields || []).find((f) => f.key === key);
      if (field && isFieldReadOnly(field)) return;
      if (typ === 'boolean') PC.draftCfg[key] = target.checked;
      else if (typ === 'number') PC.draftCfg[key] = target.value === '' ? 0 : Number(target.value);
      else PC.draftCfg[key] = target.value;
      refreshSchemaLiveState(rec);
      return;
    }
    if (target.classList.contains('sf-sub-input')) {
      const lk = target.dataset.listKey;
      const idx = Number(target.dataset.idx);
      const sk = target.dataset.subKey;
      const typ = target.dataset.type;
      if (!Array.isArray(PC.draftCfg[lk])) PC.draftCfg[lk] = [];
      if (!PC.draftCfg[lk][idx]) PC.draftCfg[lk][idx] = {};
      if (typ === 'boolean') PC.draftCfg[lk][idx][sk] = target.checked;
      else if (typ === 'number') PC.draftCfg[lk][idx][sk] = target.value === '' ? 0 : Number(target.value);
      else PC.draftCfg[lk][idx][sk] = target.value;
    }
  }

  /* =====================================================================
   * 5. Plugin Actions (Toggle, Save Config, Reset, Reload, Install, Uninstall)
   * ===================================================================== */
  async function togglePluginById(id, enabled) {
    const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta && p.meta.id === id);
    if (rec && isRequiredPlugin(rec) && !enabled) {
      toast(`「${rec.meta.name}」为核心内置插件，不可关闭`, 'warn');
      renderPluginCenter();
      return;
    }
    try {
      const r = await api('/api/kernel/plugins/toggle', { body: { id, enabled: !!enabled } });
      if (r && r.state) {
        setKernelState(r.state);
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      if (!r || !r.ok) {
        toast(`插件状态切换异常：${friendlyErr((r && r.error) || '未知错误')}`, 'bad');
      } else {
        toast(`已${enabled ? '启用' : '停用'}插件并热更新工作台`, 'ok');
        if (B().refreshDevices) B().refreshDevices(false);
        if (B().reloadCurrentSession) B().reloadCurrentSession();
      }
    } catch (e) {
      toast('切换插件状态失败：' + friendlyErr(e.message), 'bad');
      renderPluginCenter();
    }
  }

  async function saveSelectedConfig(id) {
    try {
      const r = await api('/api/kernel/plugins/config', { body: { id, config: PC.draftCfg } });
      if (r && r.state) {
        setKernelState(r.state);
        if (r.config) PC.draftCfg = JSON.parse(JSON.stringify(r.config));
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      if (!r || !r.ok) {
        toast(`保存失败：${(r && r.error) || '校验未通过'}`, 'bad', 5000);
        return;
      }
      toast('配置已保存并热生效', 'ok');
      if (B().loadInspect) B().loadInspect();
      if (B().reloadCurrentSession) B().reloadCurrentSession();
    } catch (e) {
      toast('保存配置失败：' + e.message, 'bad');
    }
  }

  async function resetSelectedConfig(id) {
    try {
      const r = await api('/api/kernel/plugins/reset', { body: { id } });
      if (r && r.state) {
        setKernelState(r.state);
        if (r.config) PC.draftCfg = JSON.parse(JSON.stringify(r.config));
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      toast('已恢复默认配置并热生效', 'ok');
      if (B().reloadCurrentSession) B().reloadCurrentSession();
    } catch (e) {
      toast('恢复默认失败：' + e.message, 'bad');
    }
  }

  async function exportPluginZip(id, btnEl) {
    if (!id) return;
    if (btnEl) btnEl.disabled = true;
    try {
      const url = `/api/plugins/${encodeURIComponent(id)}/export`;
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          if (ct.includes('application/json')) {
            const errJson = await res.json();
            if (errJson && errJson.error) msg = errJson.error;
          } else {
            const txt = (await res.text()).trim();
            if (txt) msg = txt;
          }
        } catch {}
        throw new Error(msg);
      }
      if (ct.includes('application/zip') || ct.includes('application/octet-stream')) {
        const blob = await res.blob();
        const a = document.createElement('a');
        const objUrl = URL.createObjectURL(blob);
        a.href = objUrl;
        a.download = `${id.replace(/[^a-zA-Z0-9._-]/g, '_')}.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
        toast(`已导出插件包 ${a.download}`, 'ok');
        return;
      }
      const data = await res.json();
      if (data && data.ok === false) {
        throw new Error(data.error || '导出失败');
      }
      const kb = data && data.size_bytes ? `${(Number(data.size_bytes) / 1024).toFixed(1)} KB` : '';
      const count = data && data.file_count ? `${data.file_count} 个文件` : '';
      const metaStr = [count, kb].filter(Boolean).join('，');
      toast(`插件包已导出${data && data.path ? '：' + data.path : ''}${metaStr ? '（' + metaStr + '）' : ''}`, 'ok');
    } catch (e) {
      toast('导出插件失败：' + friendlyErr(e.message), 'bad');
    } finally {
      if (btnEl) btnEl.disabled = false;
    }
  }

  async function reloadPluginById(id) {
    try {
      const r = await api('/api/kernel/plugins/reload', { body: { id } });
      if (r && r.state) {
        setKernelState(r.state);
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      toast(r && r.ok ? '插件已热重载' : ('重载失败：' + (r && r.error)), r && r.ok ? 'ok' : 'bad');
    } catch (e) {
      toast('热重载失败：' + e.message, 'bad');
    }
  }

  async function uninstallPluginById(id) {
    if (!window.confirm(`确定永久卸载外部插件「${id}」？此操作会立即回收它的所有扩展点与界面插槽。`)) return;
    try {
      const r = await api('/api/kernel/plugins/uninstall', { body: { id } });
      if (r && r.state) {
        setKernelState(r.state);
        PC.selectedId = '';
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      toast('外部插件已卸载并回收全部扩展', 'ok');
      if (B().reloadCurrentSession) B().reloadCurrentSession();
    } catch (e) {
      toast('卸载失败：' + e.message, 'bad');
    }
  }

  /* ---- External Plugin Preview & Install Modal ---- */
  async function pickAndPreviewExternal(asDir) {
    try {
      let r;
      if (asDir) {
        r = await pickPathWithFallback('/api/dialog/pick-folder', { initial_dir: PC.state ? PC.state.plugins_dir : '' }, '请输入插件目录路径');
      } else {
        r = await pickPathWithFallback('/api/dialog/open-file', {
          title: '选择 PktPath 外部插件包 (.pktplugin / .zip / .json)',
          filter: 'PktPath Plugin (*.pktplugin;*.zip;*.json)|*.pktplugin;*.zip;*.json|All Files (*.*)|*.*',
        }, '请输入插件包路径');
      }
      if (!r || r.cancelled || !r.path) return;
      const pv = await api('/api/kernel/plugins/preview', { body: { path: r.path } });
      PC.pendingInstallPath = r.path;
      PC.pendingPreview = normalizePreview(pv);
      openInstallModal(PC.pendingPreview);
    } catch (e) {
      toast('预览外部插件失败：' + e.message, 'bad');
    }
  }

  function openInstallModal(pv) {
    const modal = $('#installModal');
    const body = $('#instBody');
    const btnOk = $('#instConfirm');
    if (!modal || !body) return;
    if (!pv || !pv.ok) {
      body.innerHTML = `<div class="pc-alert-bad">❌ 无法安装该插件：${esc((pv && pv.error) || '格式无效')}</div>`;
      if (btnOk) btnOk.disabled = true;
    } else {
      const caps = (pv.capabilities || []).map((c) => `<li>${esc(c)}</li>`).join('');
      const warns = (pv.warnings || []).map((w) => `<div class="pc-alert-warn">⚠ ${esc(w)}</div>`).join('');
      const hasBpf = Boolean(pv.has_kernel_bpf);
      const bpfObjects = Array.isArray(pv.kernel_bpf_objects) ? pv.kernel_bpf_objects : [];
      const bpfHooks = Array.isArray(pv.kernel_bpf_hooks) ? pv.kernel_bpf_hooks : [];
      const sig = (Wave1() && typeof Wave1().describePluginSignature === 'function')
        ? Wave1().describePluginSignature(pv)
        : { status: 'unsigned', trust: 'none', label: '未签名', badgeClass: 'badge-muted', boxClass: 'is-muted', blocked: false, detail: '', fingerprint: null };
      const badges = [];
      badges.push(`<span class="badge ${esc(sig.badgeClass)}" id="instSigBadge">${esc(sig.label)}</span>`);
      if (hasBpf) badges.push('<span class="badge badge-bad">含内核 eBPF 字节码</span>');
      if ((pv.sock_fields || []).length) badges.push(`<span class="badge">BTF 字段 ×${pv.sock_fields.length}</span>`);
      if ((pv.qdiscs || []).length) badges.push(`<span class="badge">自定义队列 ×${pv.qdiscs.length}</span>`);
      if (pv.analyzer_count) badges.push(`<span class="badge badge-ok">后分析 Hook ×${pv.analyzer_count}</span>`);
      if (pv.exporter_count) badges.push(`<span class="badge badge-ok">导出器 ×${pv.exporter_count}</span>`);
      if (pv.ui_slot_count) badges.push(`<span class="badge badge-violet">界面插槽 ×${pv.ui_slot_count}</span>`);
      if (pv.schema_fields) badges.push(`<span class="badge badge-muted">可视化配置项 ×${pv.schema_fields}</span>`);

      let bpfWarningHtml = '';
      if (hasBpf) {
        const objRows = bpfObjects.length
          ? bpfObjects.map((o) => {
              const shortSha = o.sha256 ? `${o.sha256.slice(0, 12)}…` : '未提供';
              return `<li><code>${esc(o.arch || 'unknown')}</code> · <code>${esc(o.path || '')}</code> <span class="muted" title="${esc(o.sha256 || '')}">(SHA256: ${esc(shortSha)})</span></li>`;
            }).join('')
          : '<li class="muted">未列出目标架构 .bpf.o 文件清单</li>';
        const hookRows = bpfHooks.length
          ? `<div class="inst-bpf-sub">声明内核挂点（${bpfHooks.length} 个）：</div><ul class="inst-bpf-list">${bpfHooks.map((h) =>
              `<li><code>${esc(h.type ? `${h.type}:${h.target}` : (h.target || h.id))}</code>${h.group ? ` <span class="badge badge-muted">${esc(h.group)}</span>` : ''}</li>`
            ).join('')}</ul>`
          : '';
        bpfWarningHtml = `
          <div class="inst-bpf-warning" id="instBpfWarning">
            <div class="inst-bpf-title">⚠️ 内核级权限提示</div>
            <p class="inst-bpf-msg">包含将在设备内核态以 root 权限加载的 eBPF 字节码，仅安装信任来源。</p>
            <label class="inst-bpf-ack">
              <input type="checkbox" id="instBpfConfirm">
              <span>我确认来源可信，同意在设备内核加载此插件</span>
            </label>
            <details class="tech-details" id="instBpfTechDetails">
              <summary>查看技术详情（${bpfObjects.length} 个字节码文件${bpfHooks.length ? ` · ${bpfHooks.length} 个内核挂点` : ''}）</summary>
              <div class="inst-bpf-sub">目标架构字节码文件：</div>
              <ul class="inst-bpf-list">${objRows}</ul>
              ${hookRows}
            </details>
          </div>`;
      }

      body.innerHTML = `
        <div class="inst-summary">
          <div class="inst-icon">${esc(pluginIcon(pv.icon, '🧩'))}</div>
          <div>
            <div class="inst-name">${esc(pv.name)} <span class="muted">v${esc(pv.version || '1.0')}</span></div>
            <div class="muted" style="font-size:12px">ID: <code>${esc(pv.id)}</code> · 类型: ${esc(pv.source_type || 'bundle')}${pv.author ? ' · 作者: ' + esc(pv.author) : ''}</div>
            ${pv.description ? `<p style="margin:6px 0 0;font-size:12.5px">${esc(pv.description)}</p>` : ''}
          </div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin:10px 0">${badges.join('')}</div>
        <div class="inst-sig-box ${esc(sig.boxClass)}" id="instSigBox">
          <div class="inst-sig-head">
            <span class="inst-sig-title">${esc(sig.label)}</span>
          </div>
          ${sig.detail ? `<div class="inst-sig-detail">${esc(sig.detail)}</div>` : ''}
          ${(sig.fingerprint || pv.signature_reason) ? `
            <details class="tech-details" id="instSigTechDetails">
              <summary>查看签名技术详情</summary>
              ${sig.fingerprint ? `<div class="tech-kv"><span>公钥指纹</span><code class="inst-sig-fp">${esc(sig.fingerprint)}</code></div>` : ''}
              ${pv.signature_reason ? `<div class="tech-kv"><span>校验说明</span><code>${esc(pv.signature_reason)}</code></div>` : ''}
            </details>` : ''}
        </div>
        ${sig.blocked ? '<div class="pc-alert-bad" id="instSigBlocked">❌ 签名无效，已禁止安装此插件包。</div>' : ''}
        ${bpfWarningHtml}
        <div class="section-title" style="margin:8px 0 4px">安装后将立即提供以下能力：</div>
        <ul class="pc-cap-list">${caps || '<li class="muted">未声明能力</li>'}</ul>
        ${warns}
      `;
      if (btnOk) btnOk.disabled = Boolean(sig.blocked || hasBpf);
    }
    modal.hidden = false;
  }

  function closeInstallModal() {
    const modal = $('#installModal');
    if (modal) modal.hidden = true;
    PC.pendingInstallPath = '';
    PC.pendingPreview = null;
  }

  async function confirmInstallExternal() {
    if (!PC.pendingInstallPath) return;
    const sigCheck = (Wave1() && typeof Wave1().describePluginSignature === 'function')
      ? Wave1().describePluginSignature(PC.pendingPreview || {})
      : { blocked: PC.pendingPreview && PC.pendingPreview.signature_status === 'invalid' };
    if (sigCheck && sigCheck.blocked) {
      toast('签名无效，禁止安装该插件', 'bad');
      return;
    }
    if (PC.pendingPreview && PC.pendingPreview.has_kernel_bpf) {
      const ack = $('#instBpfConfirm');
      if (!ack || !ack.checked) {
        toast('请先勾选确认同意加载设备内核态 eBPF 字节码', 'warn');
        return;
      }
    }
    const p = PC.pendingInstallPath;
    closeInstallModal();
    try {
      const r = await api('/api/kernel/plugins/install', { body: { path: p } });
      if (r && r.state) {
        setKernelState(r.state);
        const installedId = (r.plugin && r.plugin.id) || r.plugin_id;
        if (installedId) {
          PC.selectedId = installedId;
          const rec = (PC.state.plugins || []).find((x) => x.meta.id === PC.selectedId);
          PC.draftCfg = rec ? JSON.parse(JSON.stringify(rec.config || {})) : {};
        }
        applyKernelStateToApp(PC.state);
        renderPluginCenter();
      }
      if (!r || !r.ok) {
        toast('安装失败：' + ((r && r.error) || '未知错误'), 'bad');
        return;
      }
      toast(`插件「${r.plugin ? r.plugin.name : ''}」已安装并立即生效！`, 'ok', 4500);
      if (B().loadInspect) B().loadInspect();
      if (B().reloadCurrentSession) B().reloadCurrentSession();
    } catch (e) {
      toast('安装外部插件失败：' + e.message, 'bad');
    }
  }

  /* =====================================================================
   * 6. Event Bindings & Boot
   * ===================================================================== */
  function bindEvents() {
    // Top workspace nav tabs
    const nav = $('#mainNav');
    if (nav) {
      nav.addEventListener('click', (e) => {
        const b = e.target.closest('.main-nav-tab');
        if (b) setMainView(b.dataset.view);
      });
    }
    const emptyOpenP = $('#btnEmptyOpenPlugins');
    if (emptyOpenP) emptyOpenP.addEventListener('click', () => setMainView('plugins'));
    const railOpenP = $('#btnRailOpenPlugins');
    if (railOpenP) railOpenP.addEventListener('click', () => setMainView('plugins'));
    const emptyOpenF = $('#btnEmptyOpenFolder');
    if (emptyOpenF) emptyOpenF.addEventListener('click', () => { if (B().openFolder) B().openFolder(); });

    // Offline transport pane buttons
    const offPick = $('#btnOfflinePick');
    if (offPick) offPick.addEventListener('click', () => { if (B().openFolder) B().openFolder(); });
    const offLatest = $('#btnOfflineLatest');
    if (offLatest) offLatest.addEventListener('click', () => {
      const st = B().getState ? B().getState() : {};
      if (st.sessions && st.sessions.length && B().showSession) {
        B().showSession(st.sessions[0].id);
      } else {
        toast('暂无本机历史会话，请先选择一个会话目录', 'warn');
      }
    });

    // Dynamic exporter buttons
    const expBar = $('#dynamicExporters');
    if (expBar) {
      expBar.addEventListener('click', (e) => {
        const b = e.target.closest('.dyn-export-btn');
        if (b) runDynamicExporter(b.dataset.exporter);
      });
    }

    // Insight sample click -> open single packet drawer directly!
    const insBar = $('#pluginInsightsBar');
    if (insBar) {
      insBar.addEventListener('click', (e) => {
        const b = e.target.closest('.ins-sample-pill');
        if (b && B().openSample) B().openSample(b.dataset.sid);
      });
    }

    // Plugin Center top toolbar
    const catBar = $('#pcCatBar');
    if (catBar) {
      catBar.addEventListener('click', (e) => {
        const b = e.target.closest('.pc-cat');
        if (!b) return;
        PC.cat = b.dataset.cat;
        $$('.pc-cat', catBar).forEach((x) => x.classList.toggle('active', x === b));
        renderPluginCenter();
      });
    }
    const pcSearch = $('#pcSearch');
    if (pcSearch) {
      pcSearch.addEventListener('input', (e) => { PC.search = e.target.value; renderPluginCenter(); });
    }
    $('#pcBtnInstallFile')?.addEventListener('click', () => pickAndPreviewExternal(false));
    $('#pcBtnInstallDir')?.addEventListener('click', () => pickAndPreviewExternal(true));
    $('#pcBtnRevealDir')?.addEventListener('click', () => {
      if (PC.state && PC.state.plugins_dir && B().revealPath) B().revealPath(PC.state.plugins_dir);
    });
    $('#pcBtnRefresh')?.addEventListener('click', () => { loadKernelState(false); toast('已刷新微内核插件清单', 'ok'); });

    // Master list click & toggle
    const pcList = $('#pcList');
    if (pcList) {
      pcList.addEventListener('click', (e) => {
        if (e.target.closest('.switch')) return;
        const item = e.target.closest('.pc-item');
        if (!item) return;
        PC.selectedId = item.dataset.pid;
        const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta.id === PC.selectedId);
        PC.draftCfg = rec ? JSON.parse(JSON.stringify(rec.config || {})) : {};
        renderPluginCenter();
      });
      pcList.addEventListener('change', (e) => {
        const t = e.target.closest('.pc-item-toggle');
        if (t) togglePluginById(t.dataset.pid, t.checked);
      });
    }

    // Detail panel actions & Schema-Form live editing
    const pcDetail = $('#pcDetail');
    if (pcDetail) {
      pcDetail.addEventListener('change', (e) => {
        if (e.target.id === 'pcDetToggle') {
          togglePluginById(e.target.dataset.pid, e.target.checked);
          return;
        }
        syncDraftFromEvent(e.target);
      });
      pcDetail.addEventListener('input', (e) => {
        syncDraftFromEvent(e.target);
      });
      pcDetail.addEventListener('toggle', (e) => {
        const det = e.target;
        if (det && det.classList && det.classList.contains('sf-group') && det.dataset.groupId) {
          PC.groupOpenState.set(`${det.dataset.pluginId || PC.selectedId}:${det.dataset.groupId}`, det.open);
        }
      }, true);
      pcDetail.addEventListener('click', async (e) => {
        const presetCard = e.target.closest('.sf-preset-card');
        if (presetCard) {
          const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta && p.meta.id === PC.selectedId);
          if (rec && rec.schema && Wave1() && typeof Wave1().applyPresetToConfig === 'function') {
            PC.draftCfg = Wave1().applyPresetToConfig(rec.schema, PC.draftCfg, presetCard.dataset.presetId);
            renderPluginDetail(rec);
          }
          return;
        }
        const saveBtn = e.target.closest('#pcBtnSaveCfg');
        if (saveBtn) { saveSelectedConfig(saveBtn.dataset.pid); return; }
        const resetBtn = e.target.closest('#pcBtnResetCfg');
        if (resetBtn) { resetSelectedConfig(resetBtn.dataset.pid); return; }
        const exportBtn = e.target.closest('#pcDetExport');
        if (exportBtn) { exportPluginZip(exportBtn.dataset.pid, exportBtn); return; }
        const reloadBtn = e.target.closest('#pcDetReload');
        if (reloadBtn) { reloadPluginById(reloadBtn.dataset.pid); return; }
        const uninstBtn = e.target.closest('#pcDetUninstall');
        if (uninstBtn) { uninstallPluginById(uninstBtn.dataset.pid); return; }

        // List add/remove card
        const addBtn = e.target.closest('.sf-list-add');
        if (addBtn) {
          const lk = addBtn.dataset.listKey;
          const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta.id === PC.selectedId);
          const field = rec && rec.schema && (rec.schema.fields || []).find((f) => f.key === lk);
          const blank = {};
          if (field && Array.isArray(field.item_fields)) {
            for (const sf of field.item_fields) {
              blank[sf.key] = sf.default !== undefined ? sf.default : (sf.type === 'boolean' ? false : sf.type === 'number' ? 0 : '');
            }
          }
          if (!Array.isArray(PC.draftCfg[lk])) PC.draftCfg[lk] = [];
          PC.draftCfg[lk].push(blank);
          renderPluginDetail(rec);
          return;
        }
        const delBtn = e.target.closest('.sf-list-del');
        if (delBtn) {
          const lk = delBtn.dataset.listKey;
          const idx = Number(delBtn.dataset.idx);
          if (Array.isArray(PC.draftCfg[lk])) PC.draftCfg[lk].splice(idx, 1);
          const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta.id === PC.selectedId);
          renderPluginDetail(rec);
          return;
        }

        // File / directory browse button inside Schema-Form
        const browseBtn = e.target.closest('.sf-browse-btn');
        if (browseBtn) {
          const key = browseBtn.dataset.key;
          const kind = browseBtn.dataset.browse;
          const filter = browseBtn.dataset.filter || '';
          try {
            const r = kind === 'dir'
              ? await pickPathWithFallback('/api/dialog/pick-folder', {}, '请输入目录路径')
              : await pickPathWithFallback('/api/dialog/open-file', { filter }, '请输入文件路径');
            if (r && !r.cancelled && r.path) {
              PC.draftCfg[key] = r.path;
              const rec = ((PC.state && PC.state.plugins) || []).find((p) => p.meta.id === PC.selectedId);
              renderPluginDetail(rec);
            }
          } catch (err) {
            toast('打开文件选择器失败：' + err.message, 'bad');
          }
        }
      });
    }

    // Workbench compact probe preset summary -> jump straight to collector plugin settings
    $('#probePresetSummary')?.addEventListener('click', (e) => {
      const btn = e.target.closest('#btnOpenProbeSettings');
      if (btn) setMainView('plugins', btn.dataset.pid || 'builtin.collector.ebpf-tc');
    });

    // Install Preview Modal
    $('#instBody')?.addEventListener('change', (e) => {
      if (e.target && e.target.id === 'instBpfConfirm') {
        const btnOk = $('#instConfirm');
        const blocked = PC.pendingPreview && PC.pendingPreview.signature_status === 'invalid';
        if (btnOk) btnOk.disabled = Boolean(blocked || !e.target.checked);
      }
    });
    $('#instClose')?.addEventListener('click', closeInstallModal);
    $('#instCancel')?.addEventListener('click', closeInstallModal);
    $('#instConfirm')?.addEventListener('click', confirmInstallExternal);
    $('#installModal')?.addEventListener('click', (e) => {
      if (e.target.id === 'installModal') closeInstallModal();
    });

    // Wire bridge hooks into app.js
    if (window.PktPathStudio) {
      window.PktPathStudio.openPluginCenter = (pid) => setMainView('plugins', pid);
      window.PktPathStudio.openWorkbench = () => setMainView('workbench');
      window.PktPathStudio._onSessionRendered = (ov) => renderSessionPluginOutputs(ov);
      window.PktPathStudio._onTransportChanged = () => syncWorkbenchVisibility(PC.state);
    }
  }

  function init() {
    bindEvents();
    loadKernelState(true);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
