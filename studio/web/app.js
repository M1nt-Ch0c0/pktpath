/* PktPath Studio · 单包路径跟踪工作台 — frontend workbench
 * 100% offline vanilla JS + hand-built SVG. No external dependencies.
 * Backend: same-origin HTTP API served by pktpath-studio.exe (see /api/* below).
 * Demo mode (no backend): open with ?demo=1 or from file://
 */
(function () {
  'use strict';

  /* =====================================================================
   * 0. Utilities
   * ===================================================================== */
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const arr = (x) => (Array.isArray(x) ? x : []);
  const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : {});
  const isNum = (x) => typeof x === 'number' && isFinite(x);
  const toNum = (x) => {
    if (isNum(x)) return x;
    if (typeof x === 'string' && x.trim() !== '' && isFinite(Number(x))) return Number(x);
    return null;
  };
  const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const debounce = (fn, ms) => { let t = 0; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const pick = (o, ...keys) => { for (const k of keys) { if (o && o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k]; } return undefined; };

  function fmtInt(n) {
    const v = toNum(n);
    if (v === null) return '—';
    return Math.round(v).toLocaleString('en-US');
  }
  /** µs formatter -> [value, unit] */
  function usParts(v) {
    const n = toNum(v);
    if (n === null) return ['—', ''];
    const a = Math.abs(n);
    if (a >= 1e6) return [(n / 1e6).toFixed(a >= 1e7 ? 1 : 2), 's'];
    if (a >= 1e4) return [(n / 1000).toFixed(a >= 1e5 ? 1 : 2), 'ms'];
    if (a >= 100) return [Math.round(n).toLocaleString('en-US'), 'µs'];
    if (a >= 10) return [n.toFixed(1), 'µs'];
    return [n.toFixed(2), 'µs'];
  }
  function fmtUs(v) { const p = usParts(v); return p[1] ? p[0] + ' ' + p[1] : p[0]; }
  function fmtBytes(n) {
    const v = toNum(n);
    if (v === null) return '—';
    if (v >= 1048576) return (v / 1048576).toFixed(2) + ' MiB';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KiB';
    return v + ' B';
  }
  function fmtPct(r) { return r === null || !isFinite(r) ? '—' : (r * 100).toFixed(r >= 0.9995 || r === 0 ? 0 : 1) + '%'; }
  function fmtTime(x) {
    if (x === null || x === undefined || x === '') return '';
    let d;
    if (isNum(x)) d = new Date(x > 1e15 ? x / 1e6 : x > 1e12 ? x : x * 1000);
    else d = new Date(String(x));
    if (isNaN(d.getTime())) return String(x);
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function fmtClock(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    const p = (n) => String(n).padStart(2, '0');
    return s >= 3600 ? `${Math.floor(s / 3600)}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}` : `${p(Math.floor(s / 60))}:${p(s % 60)}`;
  }
  function parseHandle(h) {
    if (isNum(h)) return h >>> 0;
    if (typeof h !== 'string') return null;
    const s = h.trim().toLowerCase();
    if (s === 'root') return 0xffffffff;
    const m = /^([0-9a-f]*):([0-9a-f]*)$/.exec(s);
    if (m) return (((parseInt(m[1] || '0', 16) & 0xffff) << 16) | (parseInt(m[2] || '0', 16) & 0xffff)) >>> 0;
    if (/^\d+$/.test(s)) return Number(s) >>> 0;
    return null;
  }
  function fmtHandle(h) {
    if (typeof h === 'string' && !/^\d+$/.test(h.trim())) return h;
    const v = parseHandle(h);
    if (v === null) return '—';
    if (v === 0xffffffff) return 'root';
    if (v === 0) return '0:';
    const maj = (v >>> 16).toString(16);
    const min = v & 0xffff;
    return min ? `${maj}:${min.toString(16)}` : `${maj}:`;
  }
  function percentile(sorted, p) {
    if (!sorted.length) return null;
    const idx = (sorted.length - 1) * p;
    const lo = Math.floor(idx), hi = Math.ceil(idx);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }
  function fmtBps(bps) {
    const v = toNum(bps);
    if (!v || v <= 0) return '';
    if (v >= 1e9) { const g = v / 1e9; return (g >= 10 || Math.abs(g - Math.round(g)) < 0.005 ? Math.round(g) : +g.toFixed(2)) + 'G'; }
    if (v >= 1e6) { const m = v / 1e6; return (m >= 10 || Math.abs(m - Math.round(m)) < 0.05 ? Math.round(m) : +m.toFixed(1)) + 'M'; }
    if (v >= 1e3) return Math.round(v / 1e3) + 'K';
    return Math.round(v) + 'bps';
  }
  function fmtRateRange(rateBps, ceilBps) {
    const r = fmtBps(rateBps), c = fmtBps(ceilBps);
    if (!r && !c) return '';
    if (r && c && r !== c) return `${r}→${c}`;
    return r || c;
  }
  function baseName(p) { return String(p || '').replace(/[\\/]+$/, '').split(/[\\/]/).pop(); }

  /* ---- domain dictionaries ---- */
  const ENDPOINT_ZH = {
    TX_OK: '交给驱动发出', NETDEV_TX_OK: '交给驱动发出', DROP: '被丢弃', CONSUME: '正常释放',
    SOCK_ENQUEUE: '投递到 socket', DELIVER_SOCK: '投递到 socket', APP_READ: '应用已读取',
    TIMEOUT_TRUNCATED: '超时截断', CONFLICT_TRUNCATED: '身份冲突隔离', BOUNDARY: '观测边界',
    OPEN: '未闭合', UNKNOWN_TAIL: '采集尾部未知', UNKNOWN: '未知',
    HANDOFF: '交给下一层', MERGED: '已合并', SEGMENTED: '已分段',
  };
  const REL_NAMES = { 1: 'CLONE', 2: 'COPY', 3: 'REPLACE', 4: 'SEGMENT', 5: 'MERGE', 6: 'HANDOFF', 7: 'SPAN_MAP' };
  const QSTATE_NAMES = { 1: 'TXQ_STOP→WAKE', 2: 'TXQ_WAKE', 3: 'BQL_LIMIT' };
  function endpointClass(ep) {
    const e = String(ep || '').toUpperCase();
    if (!e) return 'warn';
    if (e.includes('DROP')) return 'bad';
    if (e === 'TX_OK' || e.includes('TX_OK') || e.includes('DELIVER') || e.includes('SOCK_ENQ') || e === 'APP_READ') return 'ok';
    if (e.includes('CONSUME') || e.includes('MERGE') || e.includes('SEGMENT') || e.includes('HANDOFF') || e === 'BOUNDARY') return 'mid';
    return 'warn';
  }
  function endpointBadge(ep) {
    const cls = { ok: 'badge-ok', bad: 'badge-bad', mid: 'badge-muted', warn: 'badge-warn' }[endpointClass(ep)];
    const zh = ENDPOINT_ZH[String(ep || '').toUpperCase()];
    return `<span class="badge ${cls}" title="${esc(zh || '')}">${esc(ep || '未知')}</span>`;
  }
  const LV_LABEL = { 1: '直接观测', 2: '契约推导', 3: '辅助旁注', 4: '缺口/未知' };
  const LV_TIP = {
    1: '探针在该位置直接命中并记录（最可信）',
    2: '由内核调用契约推导得出（例如 enqueue 返回成功 ⇒ 已入队）',
    3: '辅助信息旁注（例如自定义插件扩展字段、socket 归属预热）',
    4: '此处证据缺失：探针未覆盖、被内联或事件丢失，时间为推断区间',
  };
  function evLevel(ev) {
    const v = ev ? ev.evidence_level : null;
    const n = toNum(v);
    if (n !== null && n >= 1 && n <= 4) return n;
    const s = String(v || ev && ev.evidence_label || '').toUpperCase();
    if (s.includes('GAP') || s.includes('缺口') || s.includes('UNKNOWN')) return 4;
    if (s.includes('ANNOT') || s.includes('旁注')) return 3;
    if (s.includes('CONTRACT') || s.includes('DERIV') || s.includes('推导')) return 2;
    return 1;
  }
  const ADMISSION_ZH = {
    filter_unknown: '过滤器无法判定', matched: '命中筛选条件', selected: '抽样入选',
    created: '建立跟踪对象', rejected: '容量/冲突被拒绝',
  };

  /* =====================================================================
   * 1. API layer (+ demo backend)
   * ===================================================================== */
  const DEMO = /[?&]demo=1\b/.test(location.search) || location.protocol === 'file:';

  async function api(path, opts) {
    opts = opts || {};
    if (DEMO) return Demo.handle(path, opts);
    const init = { method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'), headers: {}, cache: 'no-store' };
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    const timeout = opts.timeout === undefined ? 60000 : opts.timeout;
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    let timer = 0;
    if (ctrl && timeout > 0) { init.signal = ctrl.signal; timer = setTimeout(() => ctrl.abort(), timeout); }
    let res;
    try {
      res = await fetch(path, init);
    } catch (e) {
      throw new Error(e && e.name === 'AbortError' ? `请求超时：${path.split('?')[0]}` : `无法连接本地服务（${(e && e.message) || e}）`);
    } finally {
      if (timer) clearTimeout(timer);
    }
    const text = await res.text();
    let data = null;
    if (text) { try { data = JSON.parse(text); } catch (_) { data = { raw: text }; } }
    if (data && data.cancelled === true) return data;
    if (!res.ok || (data && data.ok === false)) {
      const msg = (data && (data.error || data.message || data.raw)) || res.statusText || `HTTP ${res.status}`;
      throw new Error(String(msg).slice(0, 400));
    }
    return data || {};
  }
  const qs = (o) => Object.keys(o).filter((k) => o[k] !== undefined && o[k] !== null && o[k] !== '')
    .map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(o[k])).join('&');

  /* =====================================================================
   * 2. State
   * ===================================================================== */
  const S = {
    transport: 'adb',
    devices: [], adbDevices: [], sshTargets: [], sshAvailable: true, availableAgents: [],
    adbMissing: false, pluginsDir: '', plugins: [], pluginSlots: null, pendingPlugin: null,
    serial: '', prepState: 'idle', prepInfo: null, prepErr: '',
    interfaces: [], iface: '', inspect: null, apps: [], uidMap: {},
    app: { uid: -1, label: '全部应用 (不限 UID)' },
    proto: '', mode: 'oneshot', sample: '1/1', duration: 10, dsample: '1/100',
    capturing: false, stopping: false, cap: null, pollTimer: 0, tickTimer: 0, lastStatus: null,
    sessions: [], sessionPaths: {}, savedPath: '', sessionId: '', overview: null, samples: [], queues: [], qIndex: {}, classIndex: {}, slowThr: 0, maxSoj: 0,
    sort: { k: 'max_sojourn_us', dir: -1 },
    filter: { q: '', uid: '', seq: '', status: 'all', prefix: null },
    shown: 300, activeSample: null, detail: null, branchIdx: 0, showRaw: false, detailToken: 0,
    es: null, devTimer: 0, quitting: false,
  };

  /* =====================================================================
   * 3. Toasts & tooltip
   * ===================================================================== */
  function toast(msg, kind, ms) {
    const el = document.createElement('div');
    el.className = 'toast ' + (kind || '');
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 320); }, ms || (kind === 'bad' ? 7000 : 3800));
  }
  const tipEl = () => $('#tooltip');
  function bindTooltip() {
    document.addEventListener('mouseover', (e) => {
      const t = e.target && e.target.closest ? e.target.closest('[data-tip]') : null;
      if (!t) { tipEl().hidden = true; return; }
      tipEl().innerHTML = t.getAttribute('data-tip');
      tipEl().hidden = false;
      placeTip(e);
    });
    document.addEventListener('mousemove', (e) => { if (!tipEl().hidden) placeTip(e); });
    document.addEventListener('mouseleave', () => { tipEl().hidden = true; });
  }
  function placeTip(e) {
    const el = tipEl();
    const w = el.offsetWidth, h = el.offsetHeight;
    let x = e.clientX + 14, y = e.clientY + 14;
    if (x + w > window.innerWidth - 8) x = e.clientX - w - 12;
    if (y + h > window.innerHeight - 8) y = e.clientY - h - 12;
    el.style.left = Math.max(4, x) + 'px';
    el.style.top = Math.max(4, y) + 'px';
  }
  /** build a data-tip attribute value from trusted (already-escaped) html */
  const tipAttr = (html) => ` data-tip="${esc(html)}"`;

  /* =====================================================================
   * 4. Theme & rail
   * ===================================================================== */
  function initTheme() {
    let t = null;
    try { t = localStorage.getItem('pktpath.theme'); } catch (_) { /* ignore */ }
    if (t !== 'light' && t !== 'dark') t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', t);
    try { if (localStorage.getItem('pktpath.rail') === 'collapsed') document.body.classList.add('rail-collapsed'); } catch (_) { /* ignore */ }
  }
  function toggleTheme() {
    const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('pktpath.theme', t); } catch (_) { /* ignore */ }
  }
  function toggleRail() {
    document.body.classList.toggle('rail-collapsed');
    try { localStorage.setItem('pktpath.rail', document.body.classList.contains('rail-collapsed') ? 'collapsed' : ''); } catch (_) { /* ignore */ }
    setTimeout(renderCharts, 260);
  }

  /* =====================================================================
   * 5. Target Devices (Android ADB + Linux SSH)
   * ===================================================================== */
  let devLoading = false;
  function switchTransport(mode) {
    S.transport = mode === 'ssh' ? 'ssh' : (mode === 'offline' ? 'offline' : 'adb');
    setSeg($('#segTransport'), S.transport);
    $('#paneADB').hidden = S.transport !== 'adb';
    $('#paneSSH').hidden = S.transport !== 'ssh';
    const po = $('#paneOffline');
    if (po) po.hidden = S.transport !== 'offline';
    if (S.transport === 'adb' && S.adbMissing && !S.serial) {
      setPrep('bad', '未检测到系统 adb：请安装 Android Platform-Tools 并加入 PATH（可切换「Linux SSH」或「离线会话」，或在「插件中心」关闭 Android 插件）');
    } else if (S.transport !== 'adb' && S.prepState === 'bad' && /未检测到系统 adb/.test($('#prepStatus').textContent || '')) {
      setPrep('idle');
    }
    renderSSHSelect();
    updateStartBtn();
    if (window.PktPathStudio && typeof window.PktPathStudio._onTransportChanged === 'function') {
      window.PktPathStudio._onTransportChanged(S.transport);
    }
  }
  async function refreshDevices(manual) {
    if (devLoading) return;
    devLoading = true;
    const btn = $('#btnRefreshDevices');
    if (manual) btn.classList.add('spinning');
    try {
      const d = await api('/api/devices', { timeout: 20000 });
      S.adbMissing = !!d.adb_missing;
      S.sshAvailable = d.ssh_available !== false;
      S.availableAgents = arr(d.available_agents);
      S.devices = arr(d.devices).filter((x) => x && x.serial);
      S.adbDevices = arr(d.adb_devices).length || S.adbMissing
        ? arr(d.adb_devices).filter((x) => x && x.serial)
        : S.devices.filter((x) => (x.transport || 'adb') === 'adb');
      S.sshTargets = arr(d.ssh_targets);
      renderDeviceSelect();
      renderSSHSelect();
      if (S.transport === 'adb' && S.adbMissing && !S.serial) {
        setPrep('bad', '未检测到系统 adb：请安装 Android Platform-Tools 并加入 PATH（可切换「Linux (SSH)」连接通用 Linux 主机，或直接打开离线历史会话）');
        if (manual) toast('未检测到系统 adb；可切换 Linux (SSH) 模式或安装 Platform-Tools', 'warn');
      } else if (!S.serial) {
        if (S.prepState === 'bad' && /未检测到系统 adb/.test($('#prepStatus').textContent || '')) setPrep('idle');
        const readyAdb = S.adbDevices.filter((x) => (x.state || 'device') === 'device');
        if (S.transport === 'adb' && readyAdb.length >= 1) {
          $('#selDevice').value = readyAdb[0].serial;
          selectDevice(readyAdb[0].serial);
        } else if (manual) {
          toast(S.devices.length ? `发现 ${S.adbDevices.length} 台 Android 设备、${S.sshTargets.length} 台 Linux SSH 主机` : '未发现设备：可连接 Android USB 或在「Linux (SSH)」中添加服务器', S.devices.length ? 'ok' : 'warn');
        }
      } else if (manual) {
        toast(`已刷新：${S.adbDevices.length} 台 Android 设备、${S.sshTargets.length} 台 Linux SSH 主机`, 'ok');
      }
    } catch (e) {
      if (manual || !S.devices.length) {
        const sel = $('#selDevice');
        if (!S.adbDevices.length) sel.innerHTML = '<option value="">设备服务暂不可用</option>';
        if (manual) toast('刷新设备失败：' + e.message, 'bad');
      }
    } finally {
      devLoading = false;
      btn.classList.remove('spinning');
      renderDevicePill();
    }
  }
  function devLabel(d) {
    if (d.transport === 'ssh' || String(d.serial || '').startsWith('ssh:')) {
      const host = d.ssh_host ? `${d.ssh_user ? d.ssh_user + '@' : ''}${d.ssh_host}${d.ssh_port && d.ssh_port !== 22 ? ':' + d.ssh_port : ''}` : d.serial;
      return `Linux SSH · ${d.model || host}${d.arch ? ' · ' + d.arch : ''}`;
    }
    const name = d.model || d.product || d.serial;
    const parts = [name, d.serial];
    if (d.android_ver) parts.push('Android ' + d.android_ver);
    return parts.join(' · ');
  }
  function renderDeviceSelect() {
    const sel = $('#selDevice');
    const cur = S.serial && !String(S.serial).startsWith('ssh:') ? S.serial : '';
    const emptyLabel = S.adbMissing ? '未检测到系统 adb（请安装 Platform-Tools）' : (S.adbDevices.length ? '请选择 Android 设备…' : '未发现 USB 设备（可切换 Linux SSH）');
    let html = `<option value="">${emptyLabel}</option>`;
    for (const d of S.adbDevices) {
      const st = d.state || 'device';
      const extra = st === 'device' ? '' : st === 'unauthorized' ? '（请在手机上允许 USB 调试）' : `（${st}）`;
      html += `<option value="${esc(d.serial)}" ${st !== 'device' ? 'disabled' : ''}>${esc(devLabel(d) + extra)}</option>`;
    }
    if (cur && !S.adbDevices.some((d) => d.serial === cur)) html += `<option value="${esc(cur)}">${esc(cur)}（已断开）</option>`;
    sel.innerHTML = html;
    sel.value = cur || '';
  }
  function renderSSHSelect() {
    const sel = $('#selSSH');
    if (!sel) return;
    const cur = String(S.serial || '').startsWith('ssh:') ? S.serial : '';
    const empty = !S.sshAvailable
      ? '系统未安装 ssh 客户端（请启用 Windows OpenSSH）'
      : (S.sshTargets.length ? '请选择 Linux SSH 主机…' : '尚未添加主机（点击右侧「+ 添加」）');
    let html = `<option value="">${empty}</option>`;
    for (const t of S.sshTargets) {
      const ser = 'ssh:' + t.id;
      const addr = `${t.user ? t.user + '@' : ''}${t.host}${t.port && t.port !== 22 ? ':' + t.port : ''}`;
      html += `<option value="${esc(ser)}">${esc(t.name || addr)} (${esc(addr)})</option>`;
    }
    sel.innerHTML = html;
    sel.value = cur;
    const delBtn = $('#btnDeleteSSH');
    if (delBtn) delBtn.hidden = !cur;
  }
  function sshFormPayload() {
    return {
      name: $('#sshName').value.trim(),
      host: $('#sshHost').value.trim(),
      port: toNum($('#sshPort').value) || 22,
      user: $('#sshUser').value.trim(),
      identity_file: $('#sshKey').value.trim(),
      use_sudo: $('#sshSudo').checked,
    };
  }
  async function testSSHConnection() {
    const req = sshFormPayload();
    if (!req.host) { toast('请先输入主机 IP 或域名', 'warn'); return; }
    const out = $('#sshTestOut');
    out.hidden = false;
    out.className = 'ssh-test-out';
    out.innerHTML = '<span class="spinner"></span> 正在通过系统 SSH 探测远程主机架构与内核…';
    try {
      const r = await api('/api/ssh/test', { body: req, timeout: 20000 });
      const pr = obj(r.probe);
      const agentTip = r.agent_key ? `已内置匹配采集器 (${r.agent_key})` : `⚠ 暂未内置 ${pr.arch || '?'} 采集器`;
      out.className = 'ssh-test-out ok';
      out.textContent = `✔ 连接成功 · ${pr.hostname || req.host} · ${pr.arch || '?'} · Linux ${pr.kernel || '?'} · 权限=${pr.root_mode || '?'} · ${agentTip}`;
    } catch (e) {
      out.className = 'ssh-test-out bad';
      out.textContent = '✖ 连接失败：' + e.message;
    }
  }
  async function saveSSHHost() {
    const req = sshFormPayload();
    if (!req.host) { toast('请输入主机 IP 或域名', 'warn'); return; }
    try {
      const r = await api('/api/ssh/targets', { body: req, timeout: 15000 });
      S.sshTargets = arr(r.targets);
      $('#sshForm').hidden = true;
      $('#sshTestOut').hidden = true;
      await refreshDevices(false);
      switchTransport('ssh');
      if (r.serial) {
        $('#selSSH').value = r.serial;
        selectDevice(r.serial);
      }
      toast(`已保存 Linux SSH 主机：${(r.target && r.target.name) || req.host}`, 'ok');
    } catch (e) {
      toast('保存 SSH 主机失败：' + e.message, 'bad');
    }
  }
  async function deleteCurrentSSH() {
    if (!String(S.serial || '').startsWith('ssh:')) return;
    const id = S.serial.slice(4);
    if (!window.confirm('确定删除该 SSH 主机配置吗？')) return;
    try {
      await api('/api/ssh/targets?' + qs({ id }), { method: 'DELETE', timeout: 10000 });
      selectDevice('');
      await refreshDevices(false);
      toast('已删除 SSH 主机配置', 'ok');
    } catch (e) {
      toast('删除失败：' + e.message, 'bad');
    }
  }
  async function pickSSHKeyFile() {
    try {
      const r = await api('/api/dialog/open-file', { body: { title: '选择 SSH 私钥文件', filter: 'All Files (*.*)|*.*' }, timeout: 0 });
      if (r && r.path) $('#sshKey').value = r.path;
    } catch (e) {
      if (!/cancel/i.test(e.message)) toast('选择私钥失败：' + e.message, 'bad');
    }
  }
  function curDevice() { return S.devices.find((d) => d.serial === S.serial) || null; }
  function renderDevicePill() {
    const dot = $('#devicePillDot'), txt = $('#devicePillText'), badge = $('#devicePillBadge');
    const d = curDevice();
    dot.className = 'dot';
    badge.hidden = true;
    if (!S.serial) {
      txt.textContent = S.devices.length ? `${S.devices.length} 台目标可用 · 请选择` : '未连接目标设备';
      if (S.devices.length) dot.classList.add('warn');
      return;
    }
    if (!d) { txt.textContent = `${S.serial} · 已断开`; dot.classList.add('bad'); return; }
    const kernel = (S.prepInfo && S.prepInfo.kernel) || d.kernel || '';
    const arch = (S.prepInfo && S.prepInfo.arch) || d.arch || '';
    const prefix = d.transport === 'ssh' ? 'SSH · ' : '';
    txt.textContent = [prefix + (d.model || d.product || d.serial), d.transport === 'ssh' ? (d.ssh_host || '') : d.serial, arch, kernel ? 'Linux ' + String(kernel).split('-')[0] : ''].filter(Boolean).join(' · ');
    $('#devicePill').title = [devLabel(d), kernel && 'kernel ' + kernel].filter(Boolean).join('\n');
    badge.hidden = false;
    if (S.prepState === 'ok') {
      const rm = String((S.prepInfo && S.prepInfo.root_mode) || d.root_mode || 'root');
      badge.className = 'badge badge-ok';
      badge.textContent = '已就绪 · ' + (/^(su|sudo|root|adb.?root|magisk|ksu|apatch)/i.test(rm) || !rm ? rm || 'root' : rm);
      badge.title = '提权方式：' + rm;
      dot.classList.add('ok');
    } else if (S.prepState === 'loading') {
      badge.className = 'badge badge-warn'; badge.textContent = '准备中…'; dot.classList.add('warn');
    } else if (S.prepState === 'bad') {
      badge.className = 'badge badge-bad'; badge.textContent = '准备失败'; badge.title = S.prepErr; dot.classList.add('bad');
    } else {
      badge.className = 'badge badge-muted'; badge.textContent = d.agent_ready ? '采集器已存在' : '待准备'; dot.classList.add('warn');
    }
  }
  function setPrep(state, msg) {
    S.prepState = state;
    const el = $('#prepStatus');
    const b = $('#prepBadge');
    if (state === 'idle') { el.hidden = true; b.hidden = true; }
    else {
      el.hidden = false;
      el.className = 'prep-status' + (state === 'ok' ? ' ok' : state === 'bad' ? ' bad' : '');
      el.innerHTML = (state === 'loading' ? '<span class="spinner"></span>' : state === 'ok' ? '✔' : '✖') + `<span>${esc(msg)}</span>`;
      b.hidden = false;
      b.className = 'badge ' + (state === 'ok' ? 'badge-ok' : state === 'bad' ? 'badge-bad' : 'badge-warn');
      b.textContent = state === 'ok' ? '已就绪' : state === 'bad' ? '失败' : '准备中';
    }
    renderDevicePill();
    updateStartBtn();
  }
  async function selectDevice(serial) {
    S.serial = serial;
    S.prepInfo = null; S.inspect = null; S.interfaces = []; S.iface = ''; S.apps = []; S.uidMap = {};
    const isSSH = String(serial || '').startsWith('ssh:');
    if ($('#btnDeleteSSH')) $('#btnDeleteSSH').hidden = !isSSH;
    renderIfaceSelect(); renderTopo(null);
    if (!serial) { setPrep('idle'); return; }
    setPrep('loading', isSSH ? '正在通过 SSH 检测架构、权限并下发对应 Linux 采集器…' : '正在准备设备：检测 root、注入采集器…');
    try {
      const p = await api('/api/device/prepare', { body: { serial }, timeout: 180000 });
      if (S.serial !== serial) return;
      S.prepInfo = p || {};
      const sha = p && p.agent_sha256 ? ' · sha ' + String(p.agent_sha256).slice(0, 8) : '';
      const archTag = p && p.arch ? ` · ${p.arch}` : '';
      setPrep('ok', `采集器已就绪 · ${p.root_mode || 'root'}${archTag}${p.kernel ? ' · 内核 ' + String(p.kernel).split('-')[0] : ''}${sha}`);
    } catch (e) {
      if (S.serial !== serial) return;
      S.prepErr = e.message;
      setPrep('bad', '准备失败：' + e.message + (isSSH ? '（请确认 SSH 密钥免密登录及 root/sudo -n 权限）' : '（请确认设备已 root 并允许 USB 调试）'));
      return;
    }
    await Promise.all([loadInspect(serial, ''), loadApps(serial)]);
  }

  /* ---- Plugin Manager Drawer & Capability Inspector ---- */
  function openPluginDrawer() {
    if (window.PktPathStudio && typeof window.PktPathStudio.openPluginCenter === 'function') {
      window.PktPathStudio.openPluginCenter();
      return;
    }
  }
  function closePluginDrawer() {
    if (window.PktPathStudio && typeof window.PktPathStudio.openWorkbench === 'function') {
      window.PktPathStudio.openWorkbench();
    }
  }
  function pluginLiveMatch(plug) {
    const ins = S.inspect;
    if (!ins || !S.serial) return null;
    const fieldsByKey = new Map();
    for (const pf of arr(ins.plugin_fields)) {
      fieldsByKey.set(`${pf.struct || 'sock'}.${pf.field}`, pf);
    }
    const adaptersById = new Map();
    for (const ad of arr(ins.adapters)) {
      adaptersById.set(ad.adapter_id, ad);
    }
    return { fieldsByKey, adaptersById };
  }
  function renderPluginManager() {
    const list = $('#plugList');
    const slotsEl = $('#plugSlots');
    const dirEl = $('#plugDirHint');
    if (dirEl) dirEl.textContent = S.pluginsDir || '';
    const sl = S.pluginSlots || { sock_used: 0, sock_max: 4, classful_used: 0, classful_max: 2, leaf_used: 0, leaf_max: 2, enabled_count: 0, total_count: 0 };
    if (slotsEl) {
      slotsEl.innerHTML = [
        `<span class="badge ${sl.sock_used > sl.sock_max ? 'badge-bad' : 'badge-muted'}">Socket 槽位 ${sl.sock_used}/${sl.sock_max}</span>`,
        `<span class="badge ${sl.classful_used > sl.classful_max ? 'badge-bad' : 'badge-muted'}">Classful 队列 ${sl.classful_used}/${sl.classful_max}</span>`,
        `<span class="badge ${sl.leaf_used > sl.leaf_max ? 'badge-bad' : 'badge-muted'}">Leaf 队列 ${sl.leaf_used}/${sl.leaf_max}</span>`,
      ].join('');
    }
    const navCnt = $('#navPluginCount');
    if (navCnt) {
      navCnt.textContent = String(sl.enabled_count);
      navCnt.className = 'badge ' + (sl.enabled_count ? 'badge-ok' : 'badge-muted');
    }
    const inlineBadge = $('#pluginCountBadge');
    if (inlineBadge) {
      inlineBadge.textContent = `${sl.enabled_count} 个已启用`;
      inlineBadge.className = 'badge ' + (sl.enabled_count ? 'badge-ok' : 'badge-muted');
    }
    if (!list) return;
    if (!S.plugins.length) {
      list.innerHTML = `<div class="empty-mini" style="padding:20px 10px">当前未加载任何外部插件（运行于 100% 纯上游 Linux 内核模式）<br>点击上方 <b>「＋ 加载 / 导入插件 (.json)」</b> 即可按需扩展 Socket BTF 字段或自定义 TC 队列能力。</div>`;
      return;
    }
    const live = pluginLiveMatch();
    list.innerHTML = S.plugins.map((p) => {
      const caps = [];
      for (const sf of arr(p.sock_field_specs)) {
        let statusHtml = '<span class="badge badge-muted">连接设备后检测 BTF</span>';
        if (!p.enabled) {
          statusHtml = '<span class="badge badge-muted">已停用</span>';
        } else if (live) {
          const hit = live.fieldsByKey.get(`${sf.struct || 'sock'}.${sf.field}`);
          if (hit && hit.resolved) statusHtml = `<span class="badge badge-ok">🟢 BTF 已解析 offset=${esc(hit.offset)}</span>`;
          else statusHtml = '<span class="badge badge-warn">⚪ 当前内核无此 BTF 字段</span>';
        }
        caps.push(`<div class="plug-cap">
          <span class="plug-cap-tag sock">SOCK BTF</span>
          <div class="plug-cap-body">
            <div>${esc(sf.summary)}</div>
            <div class="plug-cap-meta">struct ${esc(sf.struct)}.${esc(sf.field)} (${esc(sf.size)}B) · role=${esc(sf.role)} · label=${esc(sf.label)}</div>
          </div>
          ${statusHtml}
        </div>`);
      }
      for (const q of arr(p.qdisc_specs)) {
        let statusHtml = '<span class="badge badge-muted">连接设备后检测符号</span>';
        if (!p.enabled) {
          statusHtml = '<span class="badge badge-muted">已停用</span>';
        } else if (live) {
          const ad = live.adaptersById.get('plugin_qdisc_' + q.id);
          if (ad && ad.enabled) statusHtml = '<span class="badge badge-ok">🟢 探针已挂载</span>';
          else if (ad && ad.missing_reason) statusHtml = `<span class="badge badge-muted" title="${esc(ad.missing_reason)}">⚪ ${esc(/not used/i.test(ad.missing_reason) ? '当前网卡未使用' : ad.missing_reason)}</span>`;
          else statusHtml = '<span class="badge badge-muted">⚪ 未匹配</span>';
        }
        const syms = q.dequeue_sym ? `${q.enqueue_sym} / ${q.dequeue_sym}` : q.enqueue_sym;
        caps.push(`<div class="plug-cap">
          <span class="plug-cap-tag qdisc">${esc(String(q.mode || '').toUpperCase())}</span>
          <div class="plug-cap-body">
            <div>${esc(q.summary)}</div>
            <div class="plug-cap-meta">kind=${esc(q.kind)} · sym=${esc(syms)}</div>
          </div>
          ${statusHtml}
        </div>`);
      }
      const errHtml = p.error ? `<div class="banner banner-bad"><span class="ico">✖</span><div>${esc(p.error)}</div></div>` : '';
      const warnHtml = arr(p.warnings).length ? `<div class="banner banner-warn"><span class="ico">⚠</span><div>${arr(p.warnings).map(esc).join('<br>')}</div></div>` : '';
      return `<div class="plug-card ${p.enabled ? '' : 'disabled'}" data-file="${esc(p.file)}">
        <div class="plug-card-head">
          <div style="flex:1;min-width:0">
            <div class="plug-card-title">
              <span>🔌 ${esc(p.name || p.file)}</span>
              ${p.version ? `<span class="badge badge-muted">v${esc(p.version)}</span>` : ''}
              <span class="plug-card-file">${esc(p.file)}</span>
            </div>
            ${p.description ? `<div class="plug-card-desc">${esc(p.description)}</div>` : ''}
          </div>
          <label class="switch" title="${p.enabled ? '点击停用此插件' : '点击启用此插件'}">
            <input type="checkbox" class="plug-toggle" data-file="${esc(p.file)}" ${p.enabled ? 'checked' : ''}>
            <span class="slider"></span>
          </label>
          <button type="button" class="btn btn-ghost btn-sm plug-del" data-file="${esc(p.file)}" title="卸载并删除该插件文件">删除</button>
        </div>
        ${errHtml}${warnHtml}
        <div class="plug-cap-list">${caps.join('') || '<div class="empty-mini">该插件未声明可用能力</div>'}</div>
      </div>`;
    }).join('');
  }
  function renderPluginPreview() {
    const box = $('#plugPreview');
    if (!box) return;
    const pend = S.pendingPlugin;
    if (!pend) { box.hidden = true; box.innerHTML = ''; return; }
    const p = pend.plugin;
    const caps = arr(p.capabilities);
    const warns = arr(p.warnings);
    box.hidden = false;
    box.innerHTML = `
      <div class="plug-preview-head">
        <h3>✨ 插件能力预览：${esc(p.name || p.file)}</h3>
        ${p.version ? `<span class="badge badge-muted">v${esc(p.version)}</span>` : ''}
        <span class="plug-card-file">${esc(p.file)}</span>
      </div>
      ${p.description ? `<div class="plug-card-desc">${esc(p.description)}</div>` : ''}
      <div style="font-size:12.5px;font-weight:600">加载该插件后，将为系统提供以下能力（共 ${caps.length} 项）：</div>
      <div class="plug-cap-list">
        ${arr(p.sock_field_specs).map((sf) => `<div class="plug-cap"><span class="plug-cap-tag sock">SOCK BTF</span><div class="plug-cap-body">${esc(sf.summary)}</div></div>`).join('')}
        ${arr(p.qdisc_specs).map((q) => `<div class="plug-cap"><span class="plug-cap-tag qdisc">${esc(String(q.mode || '').toUpperCase())}</span><div class="plug-cap-body">${esc(q.summary)}</div></div>`).join('')}
        ${!caps.length ? '<div class="empty-mini">未检测到有效能力声明</div>' : ''}
      </div>
      ${warns.length ? `<div class="banner banner-warn"><span class="ico">⚠</span><div>${warns.map(esc).join('<br>')}</div></div>` : ''}
      <div class="plug-preview-actions">
        <button type="button" class="btn btn-primary btn-sm" id="btnConfirmImportPlugin">✔ 确认加载此插件</button>
        <button type="button" class="btn btn-ghost btn-sm" id="btnCancelImportPlugin">取消</button>
      </div>`;
  }
  async function startImportPlugin() {
    try {
      const picked = await api('/api/dialog/open-file', {
        body: { title: '选择 PktPath 插件文件 (.json)', filter: 'PktPath Plugin (*.json)|*.json|All Files (*.*)|*.*' },
        timeout: 0,
      });
      if (!picked || picked.cancelled || !picked.path) return;
      const prev = await api('/api/plugins/preview', { body: { path: picked.path }, timeout: 15000 });
      S.pendingPlugin = { path: picked.path, plugin: prev.plugin };
      renderPluginPreview();
    } catch (e) {
      if (!/cancel/i.test(e.message)) toast('读取插件失败：' + e.message, 'bad');
    }
  }
  async function confirmImportPlugin() {
    if (!S.pendingPlugin) return;
    const req = S.pendingPlugin.path ? { path: S.pendingPlugin.path } : { filename: S.pendingPlugin.filename, content: S.pendingPlugin.content };
    try {
      const r = await api('/api/plugins/import', { body: req, timeout: 15000 });
      const imp = r.imported || S.pendingPlugin.plugin;
      S.pendingPlugin = null;
      S.plugins = arr(r.plugins);
      S.pluginSlots = r.slots || S.pluginSlots;
      renderPluginPreview();
      renderPluginManager();
      const capSummary = arr(imp && imp.capabilities).slice(0, 2).join('；') || '已注册到插件目录';
      toast(`已加载插件「${(imp && imp.name) || 'plugin'}」：${capSummary}`, 'ok', 6500);
      if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface);
    } catch (e) {
      toast('导入插件失败：' + e.message, 'bad');
    }
  }
  async function togglePlugin(file, enabled) {
    try {
      const r = await api('/api/plugins/toggle', { body: { file, enabled }, timeout: 10000 });
      S.plugins = arr(r.plugins);
      S.pluginSlots = r.slots || S.pluginSlots;
      renderPluginManager();
      toast(`${enabled ? '已启用' : '已停用'}插件 ${file}`, 'ok');
      if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface);
    } catch (e) {
      toast('切换插件状态失败：' + e.message, 'bad');
      loadPlugins();
    }
  }
  async function deletePlugin(file) {
    if (!window.confirm(`确定卸载并删除插件文件 ${file} 吗？`)) return;
    try {
      const r = await api('/api/plugins/delete', { body: { file }, timeout: 10000 });
      S.plugins = arr(r.plugins);
      S.pluginSlots = r.slots || S.pluginSlots;
      renderPluginManager();
      toast(`已卸载插件 ${file}`, 'ok');
      if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface);
    } catch (e) {
      toast('卸载插件失败：' + e.message, 'bad');
    }
  }
  async function loadPlugins() {
    try {
      const d = await api('/api/plugins', { timeout: 10000 });
      S.pluginsDir = d.plugins_dir || '';
      S.plugins = arr(d.plugins);
      S.pluginSlots = d.slots || null;
      renderPluginManager();
    } catch (_) { /* ignore */ }
  }

  /* ---- interfaces & topology ---- */
  function ifaceAddrs(it) {
    const a = it.addrs;
    if (Array.isArray(a)) return a.map(String).filter(Boolean);
    if (typeof a === 'string') return a.split(/[\s,]+/).filter(Boolean);
    return [];
  }
  async function loadInspect(serial, dev) {
    const tree = $('#topoTree');
    tree.innerHTML = '<div class="empty-mini"><span class="spinner"></span> 正在读取网卡与队列拓扑…</div>';
    $('#capBadge').className = 'badge badge-muted';
    $('#capBadge').textContent = '检测中';
    try {
      const plugins = ($('#chkPlugins') && $('#chkPlugins').checked) ? '1' : '0';
      const d = await api('/api/device/inspect?' + qs({ serial, dev, scope: $('#selScope').value || 'tc-egress', plugins }), { timeout: 60000 });
      if (S.serial !== serial) return;
      const ifs = arr(d.interfaces).filter((x) => x && x.name);
      if (ifs.length) S.interfaces = ifs;
      S.inspect = obj(d.inspect);
      if (!S.iface) {
        const names = S.interfaces.map((x) => x.name);
        S.iface = dev || S.inspect.dev || (names.includes('wlan0') ? 'wlan0' : (S.interfaces.find((x) => /up/i.test(x.state || '') && x.name !== 'lo') || S.interfaces[0] || {}).name || '');
      }
      renderIfaceSelect();
      renderTopo(S.inspect);
      renderPluginManager();
    } catch (e) {
      if (S.serial !== serial) return;
      tree.innerHTML = `<div class="empty-mini">读取失败：${esc(e.message)}</div>`;
      $('#capBadge').className = 'badge badge-bad';
      $('#capBadge').textContent = '检测失败';
      if (!S.iface && !S.interfaces.length) { S.iface = dev || 'wlan0'; renderIfaceSelect(); }
    }
    updateStartBtn();
  }
  function renderIfaceSelect() {
    const sel = $('#selIface');
    if (!S.serial) { sel.innerHTML = '<option value="">请先选择设备</option>'; sel.disabled = true; return; }
    const list = S.interfaces.slice().sort((a, b) => {
      const sc = (x) => (x.name === 'wlan0' ? 0 : /up/i.test(x.state || '') ? 1 : x.name === 'lo' ? 9 : 5);
      return sc(a) - sc(b) || String(a.name).localeCompare(String(b.name));
    });
    if (S.iface && !list.some((x) => x.name === S.iface)) list.unshift({ name: S.iface, state: '', addrs: [] });
    if (!list.length) { sel.innerHTML = '<option value="">读取中…</option>'; sel.disabled = true; return; }
    sel.innerHTML = list.map((it) => {
      const addrs = ifaceAddrs(it).filter((a) => !/^fe80/i.test(a));
      const ip = addrs.find((a) => /^\d+\.\d+\.\d+\.\d+/.test(a)) || addrs[0] || '';
      const st = it.state ? String(it.state).toUpperCase() : '';
      return `<option value="${esc(it.name)}">${esc([it.name, ip.replace(/\/\d+$/, ''), st].filter(Boolean).join(' · '))}</option>`;
    }).join('');
    sel.value = S.iface;
    sel.disabled = S.capturing;
  }
  const ADAPTER_ZH = {
    l2_tc_egress_core: 'TC 队列与驱动发包核心',
    l2_qdisc_htb: 'HTB 分层令牌桶', l2_htb: 'HTB 分层令牌桶',
    l2_qdisc_fq_codel: 'fq_codel 公平队列', l2_fq_codel: 'fq_codel 公平队列',
    l2_qdisc_pfifo: 'pfifo_fast 默认队列', l2_pfifo_fast: 'pfifo_fast 默认队列',
    l2_qdisc_fifo: 'pfifo / bfifo 叶子队列',
    l2_qdisc_sfq: 'SFQ 公平队列',
    l2_tc_classify: 'TC 子类归属 (classid)',
    l2_qdisc_requeue: '驱动忙重入队 (gso_skb)', l2_driver_requeue: '驱动忙重入队 (gso_skb)',
    l2_skb_transforms: 'SKB 克隆与包头扩展',
    l2_txq_qstate: '驱动队列停启背压 (TXQ)', l2_txq_state: '驱动队列停启背压 (TXQ)',
    l1_sock_attribution: '应用 UID / Socket 归属', l1_sock_owner: '应用 UID / Socket 归属',
    l1_sendmsg_profile: '发送线程 TID 精确定位', l1_sendmsg: '发送线程 TID 精确定位',
    l1_sock_plugins: '自定义 Socket 插件',
  };
  const ADAPTER_EN_ZH = {
    'TC/Qdisc & Driver Egress Core': 'TC 队列与驱动发包核心',
    'HTB Classful Qdisc Adapter': 'HTB 分层令牌桶',
    'fq_codel Leaf Qdisc Adapter': 'fq_codel 公平队列',
    'pfifo_fast Leaf Adapter': 'pfifo_fast 默认队列',
    'pfifo/bfifo HTB Leaf Adapter': 'pfifo / bfifo 叶子队列',
    'SFQ Leaf Qdisc Adapter': 'SFQ 公平队列',
    'TC Filter & Class Attribution': 'TC 子类归属 (classid)',
    'Driver BUSY Requeue Adapter': '驱动忙重入队 (gso_skb)',
    'SKB Clone & Head Expand': 'SKB 克隆与包头扩展',
    'TXQ Stop/Wake Backpressure': '驱动队列停启背压 (TXQ)',
    'Standard Linux Socket Owner': '应用 UID / Socket 归属',
    'Exact sendmsg TID & Create TS': '发送线程 TID 精确定位',
    'Runtime Socket Field Plugins': '自定义 Socket 插件',
  };
  function formatAdapterPill(a) {
    const id = String(a.adapter_id || '').trim();
    const rawName = String(a.name || id || '?').trim();
    const isPlug = !!a.plugin;
    const zhBase = ADAPTER_ZH[id] || ADAPTER_EN_ZH[rawName] || rawName.replace(/ (Adapter|Qdisc Adapter|Leaf Qdisc Adapter)$/, '');
    const zh = isPlug ? '🔌 ' + zhBase : zhBase;
    const mr = String(a.missing_reason || '').trim();
    if (a.enabled && !mr) {
      const tip = `<div class="tt-title">🟢 ${esc(zh)}</div>状态：已完整启用（${isPlug ? '外部 JSON 插件探针正常挂载' : '全部内核探针正常挂载'}）${id ? `<br><span style="opacity:.7">ID: ${esc(id)}</span>` : ''}`;
      return `<span class="badge badge-ok"${tipAttr(tip)}>🟢 ${esc(zh)}</span>`;
    }
    if (a.enabled && mr) {
      const pm = /^partial\s*\((\d+\/\d+)/i.exec(mr);
      const suf = ' · 部分可用' + (pm ? ` (${pm[1]})` : '');
      const tip = `<div class="tt-title">🟡 ${esc(zh)}（部分可用）</div>个别辅助内核函数被编译器内联，<b>不影响主队列驻留耗时与路径重建</b>。<br><span style="opacity:.78">内核详情：${esc(mr)}</span>`;
      return `<span class="badge badge-warn"${tipAttr(tip)}>🟡 ${esc(zh + suf)}</span>`;
    }
    let suf = ' · 按需未开', desc = '当前采集配置无需此探针，已正常跳过。';
    if (/not used on target device/i.test(mr)) {
      suf = ' · 当前网卡未使用';
      desc = '当前网卡未挂载该类型队列，已自动跳过，无需开启。';
    } else if (/disabled\s*\(default profile\)/i.test(mr)) {
      suf = ' · 默认关闭（采集模式可开）';
      desc = '默认关闭以节省开销；如需精确发包线程 TID 与创建时间，勾选下方「精准发包线程与创建时间 (sendmsg)」即可。';
    } else if (/no plugin|disabled/i.test(mr)) {
      suf = ' · 未加载外部插件';
      desc = '未加载对应 JSON 插件，已按标准 Linux 内核模式运行。';
    } else if (/BTF|field/i.test(mr)) {
      suf = ' · 当前内核无对应 BTF 字段';
      desc = '插件声明的结构体字段在当前内核 BTF 中不存在，已安全跳过，不影响标准路径跟踪。';
    } else if (/absent\/inlined|inlined|ambiguous ThinLTO|absent/i.test(mr)) {
      suf = ' · 可选（内核已内联）';
      desc = '该可选辅助函数在当前内核已被编译器内联，由契约推导自动兜底，不影响队列耗时测量。';
    }
    const tip = `<div class="tt-title">⚪ ${esc(zh)}${esc(suf)}</div>${esc(desc)}${mr ? `<br><span style="opacity:.75">内核说明：${esc(mr)}</span>` : ''}`;
    return `<span class="badge badge-muted"${tipAttr(tip)}>⚪ ${esc(zh + suf)}</span>`;
  }
  function renderTopo(ins) {
    const tree = $('#topoTree'), caps = $('#capList'), cb = $('#capBadge');
    if (!ins) { tree.innerHTML = '<div class="empty-mini">选择设备后自动检测</div>'; caps.innerHTML = ''; cb.className = 'badge badge-muted'; cb.textContent = '未检测'; return; }
    const qd = arr(ins.qdiscs).filter((q) => q && (q.kind || q.handle !== undefined));
    const clsList = arr(ins.classes).filter((c) => c && (c.kind || c.handle !== undefined));
    const qNodes = qd.map((q) => ({ type: 'qdisc', q, h: parseHandle(q.handle), p: parseHandle(q.parent), children: [] }));
    const cNodes = clsList.map((c) => ({ type: 'class', c, h: parseHandle(c.handle), p: parseHandle(c.parent), leaf: parseHandle(c.leaf), children: [], autoLeafKind: '', autoLeafQ: null }));

    const classByH = new Map();
    cNodes.forEach((cn) => { if (cn.h !== null && cn.h !== 0) classByH.set(cn.h, cn); });

    const qByMaj = new Map();
    qNodes.forEach((qn) => {
      if (qn.h !== null && qn.h !== 0 && !qByMaj.has(qn.h >>> 16)) qByMaj.set(qn.h >>> 16, qn);
      else if (qn.h === 0 && (qn.p === 0xffffffff || String(qn.q.kind || '').toLowerCase() === 'mq')) qByMaj.set(0, qn);
    });

    const roots = [];
    // 1. Nest classes: under parent class if present, else under owning qdisc (matching major handle)
    cNodes.forEach((cn) => {
      const parClass = cn.p !== null && cn.p !== 0 && cn.p !== 0xffffffff ? classByH.get(cn.p) : null;
      if (parClass && parClass !== cn) {
        parClass.children.push(cn);
      } else if (cn.h !== null && qByMaj.has(cn.h >>> 16)) {
        qByMaj.get(cn.h >>> 16).children.push(cn);
      } else {
        roots.push(cn);
      }
    });

    // 2. Nest qdiscs: root/clsact at top; child qdiscs directly under matching class when classes exist
    qNodes.forEach((qn) => {
      const isRootOrIng = qn.p === null || qn.p === 0xffffffff || qn.p === 0 || ((qn.p & 0xffff0000) >>> 0) === 0xffff0000;
      if (isRootOrIng) {
        roots.push(qn);
        return;
      }
      const parClass = classByH.get(qn.p);
      if (parClass) {
        const k = String(qn.q.kind || '').toLowerCase();
        if (qn.h === 0 && /^(pfifo|bfifo|pfifo_head_drop|pfifo_fast)$/.test(k)) {
          parClass.autoLeafKind = qn.q.kind || k;
          parClass.autoLeafQ = qn.q;
          return; // hide redundant invisible 0: leaf row; show badge on leaf class instead
        }
        parClass.children.push(qn);
        return;
      }
      const parQ = qByMaj.get(qn.p >>> 16);
      if (parQ && parQ !== qn) parQ.children.push(qn);
      else roots.push(qn);
    });

    const sortKids = (list) => list.sort((a, b) => ((a.h === null ? 0 : a.h) - (b.h === null ? 0 : b.h)));
    sortKids(roots);
    [...qNodes, ...cNodes].forEach((n) => sortKids(n.children));
    cNodes.forEach((cn) => {
      if (!cn.autoLeafKind && cn.children.length === 0 && String(cn.c.kind || '').toLowerCase() === 'htb') {
        cn.autoLeafKind = 'pfifo';
      }
    });

    const fmtClsHandle = (h, raw) => {
      if (h !== null && (h >>> 16) === 0 && (h & 0xffff) !== 0) return ':' + (h & 0xffff).toString(16);
      return fmtHandle(raw);
    };
    const renderNode = (n, depth, parentHasClass) => {
      if (depth > 14) return '';
      if (n.type === 'class') {
        const c = n.c;
        const kind = String(c.kind || '').toLowerCase();
        const hDisp = fmtClsHandle(n.h, c.handle);
        const rate = fmtRateRange(c.rate_bps, c.ceil_bps);
        const prio = kind === 'htb' && c.prio !== undefined && c.prio !== null ? `<span class="cmeta">prio ${esc(c.prio)}</span>` : '';
        const rateHtml = rate ? `<span class="crate">${esc(rate)}</span>` : '';
        const leafTag = n.autoLeafKind && n.children.length === 0 ? `<span class="ctag">${esc(n.autoLeafKind)} 叶子</span>` : '';
        const pkts = toNum(c.packets) || 0;
        const pktHtml = pkts > 0 ? `<span class="cpkt">${esc(fmtInt(pkts))} pkt</span>` : '';
        const tipRows = [
          c.parent !== undefined && c.parent !== null ? ['上级 parent', fmtClsHandle(n.p, c.parent)] : null,
          rate ? ['速率 / 上限', `${fmtBps(c.rate_bps) || '—'} / ${fmtBps(c.ceil_bps) || '—'}`] : null,
          kind === 'htb' && c.prio !== undefined ? ['优先级 prio', String(c.prio)] : null,
          toNum(c.quantum) ? ['quantum', fmtBytes(c.quantum)] : null,
          c.packets !== undefined ? ['累计发送', `${fmtInt(pkts)} pkt (${fmtBytes(c.bytes || 0)})`] : null,
          toNum(c.drops) ? ['丢包 drops', fmtInt(c.drops)] : null,
          toNum(c.overlimits) ? ['限速/借用 overlimits', fmtInt(c.overlimits)] : null,
          n.autoLeafKind && n.children.length === 0 ? ['默认叶子队列', `${n.autoLeafKind} @ ${hDisp}`] : null,
        ].filter(Boolean);
        const tip = `<div class="tt-title">子类 class ${esc(c.kind || '')} ${esc(hDisp)}</div>`
          + (tipRows.length ? `<table>${tipRows.map(([k, v]) => `<tr><td>${esc(k)}</td><td class="r">${esc(v)}</td></tr>`).join('')}</table>` : '');
        const kids = n.children.length ? `<ul>${n.children.map((ch) => renderNode(ch, depth + 1, true)).join('')}</ul>` : '';
        return `<li><span class="cnode"${tipAttr(tip)}><span class="ck">class ${esc(c.kind || '')}</span><span class="ch">${esc(hDisp)}</span>${prio}${rateHtml}${leafTag}${pktHtml}</span>${kids}</li>`;
      }

      const q = n.q;
      const qk = String(q.kind || '?');
      const via = !parentHasClass && n.p !== null && n.p !== 0xffffffff && n.p !== 0 && ((n.p & 0xffff0000) >>> 0) !== 0xffff0000
        ? ` <span class="g">via ${esc(fmtClsHandle(n.p, q.parent))}</span>` : '';
      const gen = q.queue_gen !== undefined && q.queue_gen !== 0 ? ` <span class="g">gen ${esc(q.queue_gen)}</span>` : '';
      const pkts = toNum(q.packets) || 0;
      const pktHtml = pkts > 0 && !n.children.length ? ` <span class="qpkt">${esc(fmtInt(pkts))} pkt</span>` : '';
      const qTipRows = [
        q.parent !== undefined && q.parent !== null ? ['挂载点 parent', fmtHandle(q.parent)] : null,
        q.queue_gen !== undefined ? ['queue_gen', String(q.queue_gen)] : null,
        q.packets !== undefined ? ['累计发送', `${fmtInt(pkts)} pkt (${fmtBytes(q.bytes || 0)})`] : null,
        toNum(q.drops) ? ['丢包 drops', fmtInt(q.drops)] : null,
        toNum(q.overlimits) ? ['overlimits', fmtInt(q.overlimits)] : null,
      ].filter(Boolean);
      const qTip = `<div class="tt-title">队列 qdisc ${esc(qk.toUpperCase())} ${esc(fmtHandle(q.handle))}</div>`
        + (qTipRows.length ? `<table>${qTipRows.map(([k, v]) => `<tr><td>${esc(k)}</td><td class="r">${esc(v)}</td></tr>`).join('')}</table>` : '');

      let childItems = n.children;
      let extraLi = '';
      if (qk.toLowerCase() === 'mq' && n.children.length > 4) {
        const idle = n.children.filter((ch) => ch.type === 'class' && (toNum(ch.c.packets) || 0) === 0 && ch.children.length === 0);
        if (idle.length > 4) {
          const idleSet = new Set(idle);
          childItems = n.children.filter((ch) => !idleSet.has(ch));
          const names = idle.map((ch) => fmtClsHandle(ch.h, ch.c.handle)).join(', ');
          const mTip = `<div class="tt-title">${idle.length} 个空闲 mq 硬件发送队列</div>尚未发送数据包 (0 pkt)：<br>${esc(names)}`;
          extraLi = `<li><span class="cnode mq-idle"${tipAttr(mTip)}>+${idle.length} 个空闲 mq 队列</span></li>`;
        }
      }
      const kids = (childItems.length || extraLi) ? `<ul>${childItems.map((ch) => renderNode(ch, depth + 1, false)).join('')}${extraLi}</ul>` : '';
      return `<li><span class="qnode"${tipAttr(qTip)}><span class="k">${esc(qk)}</span>${esc(fmtHandle(q.handle))}${via}${gen}${pktHtml}</span>${kids}</li>`;
    };
    tree.innerHTML = roots.length ? `<ul>${roots.map((r) => renderNode(r, 0, false)).join('')}</ul>`
      : '<div class="empty-mini">该网卡未配置 qdisc（或为 noqueue 直通）</div>';

    const ads = arr(ins.adapters);
    const enabled = ads.filter((a) => a.enabled).length;
    const partial = !!ins.partial_coverage;
    cb.className = 'badge ' + (partial ? 'badge-warn' : 'badge-ok');
    cb.textContent = partial ? '部分覆盖' : '能力完整';
    let html = '';
    if (ads.length) {
      html += `<div class="cap-legend">
        <span class="cap-legend-item">🟢 已启用</span>
        <span class="cap-legend-item">🟡 部分可用（个别辅助函数内联，不影响队列耗时）</span>
        <span class="cap-legend-item">⚪ 按需未开 / 当前网卡无需（正常跳过）</span>
      </div>`;
    }
    if (ins.kernel_release) html += `<span class="badge badge-muted" title="${esc(ins.kernel_release)}">内核 ${esc(String(ins.kernel_release).split('-')[0])}</span>`;
    if (ads.length) html += `<span class="badge ${partial ? 'badge-warn' : 'badge-ok'}">已启用 ${enabled}/${ads.length} 项</span>`;
    const bud = obj(ins.budgets);
    if (bud.estimated_bpf_bytes) html += `<span class="badge badge-muted">BPF 内存 ≈ ${esc(fmtBytes(bud.estimated_bpf_bytes))}</span>`;
    for (const a of ads) html += formatAdapterPill(a);
    caps.innerHTML = html;
  }

  /* ---- apps (searchable combo) ---- */
  const SPECIAL_APPS = [
    { uid: -1, pkg: '全部应用 (不限 UID)', special: true, kw: 'all any 全部 不限' },
    { uid: 0, pkg: 'root · 系统命令 (ping / iperf 等)', special: true, kw: 'root ping iperf 系统 命令' },
    { uid: 2000, pkg: 'shell · adb shell 下运行的命令', special: true, kw: 'shell adb ping 命令' },
    { uid: 1000, pkg: 'system · 系统服务', special: true, kw: 'system 系统' },
  ];
  const APP_ALIAS = {
    wechat: 'com.tencent.mm', weixin: 'com.tencent.mm', '微信': 'com.tencent.mm', qq: 'com.tencent.mobileqq',
    douyin: 'com.ss.android.ugc.aweme', '抖音': 'com.ss.android.ugc.aweme', tiktok: 'aweme',
    bilibili: 'tv.danmaku.bili', 'b站': 'tv.danmaku.bili',
    taobao: 'com.taobao.taobao', '淘宝': 'com.taobao.taobao', chrome: 'com.android.chrome', '浏览器': 'browser',
    weibo: 'com.sina.weibo', '微博': 'com.sina.weibo', kuaishou: 'com.smile.gifmaker', '快手': 'com.smile.gifmaker',
    '王者': 'com.tencent.tmgp.sgame', game: 'com.tencent.tmgp', '游戏': 'tmgp', ping: 'ping',
  };
  async function loadApps(serial) {
    try {
      const d = await api('/api/device/apps?' + qs({ serial }), { timeout: 60000 });
      if (S.serial !== serial) return;
      S.apps = arr(d.apps).filter((a) => a && a.pkg).map((a) => ({ pkg: String(a.pkg), uid: toNum(a.uid) }));
      S.uidMap = {};
      for (const a of S.apps) { if (a.uid !== null) (S.uidMap[a.uid] = S.uidMap[a.uid] || []).push(a.pkg); }
      if (S.overview) renderTable();
    } catch (e) {
      if (S.serial === serial) toast('读取应用列表失败：' + e.message, 'warn');
    }
  }
  function matchApps(q) {
    q = String(q || '').trim().toLowerCase();
    const out = [];
    for (const s of SPECIAL_APPS) {
      if (!q || s.kw.includes(q) || String(s.uid) === q || s.pkg.toLowerCase().includes(q)) out.push(s);
    }
    const targets = [];
    if (q.length >= 2) for (const k of Object.keys(APP_ALIAS)) { if (k.startsWith(q) || q.startsWith(k)) targets.push(APP_ALIAS[k]); }
    const seen = new Set();
    const apps = S.apps.filter((a) => {
      const p = a.pkg.toLowerCase();
      return !q || p.includes(q) || String(a.uid) === q || targets.some((t) => p.includes(t));
    });
    apps.sort((a, b) => {
      const sa = q && a.pkg.toLowerCase().startsWith(q) ? 0 : 1, sb = q && b.pkg.toLowerCase().startsWith(q) ? 0 : 1;
      return sa - sb || a.pkg.localeCompare(b.pkg);
    });
    for (const a of apps) {
      if (seen.has(a.pkg)) continue;
      seen.add(a.pkg);
      out.push({ uid: a.uid, pkg: a.pkg, shared: (S.uidMap[a.uid] || []).length > 1 });
      if (out.length > 120) break;
    }
    if (!out.length && /^\d+$/.test(q)) out.push({ uid: Number(q), pkg: `UID ${q}（手动指定）`, special: true });
    return out;
  }
  let comboItems = [], comboHl = -1;
  function renderCombo() {
    const list = $('#appList');
    comboItems = matchApps($('#appSearch').value);
    if (!S.apps.length && S.serial && S.prepState === 'ok') comboItems.push({ hint: '应用列表加载中…' });
    else if (!S.serial) comboItems.push({ hint: '连接设备后可按包名搜索' });
    comboHl = comboItems.findIndex((x) => !x.hint);
    list.innerHTML = comboItems.map((it, i) => it.hint
      ? `<div class="empty-mini">${esc(it.hint)}</div>`
      : `<button type="button" class="combo-item ${it.special ? 'special' : ''} ${i === comboHl ? 'hl' : ''}" data-i="${i}">
           <span class="pkg">${esc(it.pkg)}${it.shared ? ' <span class="muted">(共享 UID)</span>' : ''}</span>
           <span class="uid">${it.uid === -1 ? 'ANY' : 'uid ' + esc(it.uid === null ? '?' : it.uid)}</span></button>`).join('');
    list.hidden = false;
  }
  function comboMove(delta) {
    const idx = comboItems.map((x, i) => (x.hint ? -1 : i)).filter((i) => i >= 0);
    if (!idx.length) return;
    let p = idx.indexOf(comboHl);
    p = clamp(p + delta, 0, idx.length - 1);
    comboHl = idx[p];
    $$('#appList .combo-item').forEach((b) => b.classList.toggle('hl', Number(b.dataset.i) === comboHl));
    const el = $(`#appList .combo-item[data-i="${comboHl}"]`);
    if (el) el.scrollIntoView({ block: 'nearest' });
  }
  function chooseApp(it) {
    if (!it || it.hint) return;
    S.app = { uid: it.uid === null ? -1 : it.uid, label: it.pkg };
    $('#appChosenText').textContent = it.uid === -1 ? it.pkg : `${it.pkg} · uid ${it.uid}`;
    $('#appSearch').value = '';
    $('#appList').hidden = true;
  }

  /* =====================================================================
   * 6. Capture control
   * ===================================================================== */
  function updateStartBtn() {
    const btn = $('#btnStart'), hint = $('#startHint');
    let why = '';
    if (!S.serial) why = '请先选择目标设备（Android ADB 或 Linux SSH）';
    else if (S.prepState === 'loading') why = '正在准备目标设备…';
    else if (S.prepState !== 'ok') why = '目标设备未就绪（需要 root / sudo）';
    else if (!S.iface) why = '请选择网卡';
    btn.disabled = !!why || S.capturing;
    btn.hidden = S.capturing;
    hint.hidden = S.capturing;
    hint.textContent = why || (S.mode === 'daemon' ? '常驻内存，卡顿时自动落盘' : `将采集 ${S.duration}s，期间请复现问题`);
  }
  function buildCaptureReq() {
    const daemon = S.mode === 'daemon';
    const port = toNum($('#inpPort').value);
    const portDir = $('#selPortDir').value;
    const thrMs = toNum($('#inpThreshold').value) || 20;
    return {
      serial: S.serial,
      mode: S.mode,
      dev: S.iface,
      scope: $('#selScope').value || 'tc-egress',
      uid: isNum(S.app.uid) ? S.app.uid : -1,
      proto: S.proto,
      src_ip: $('#inpSrcIp').value.trim(),
      dst_ip: $('#inpDstIp').value.trim(),
      src_port: port && portDir === 'src' ? Math.trunc(port) : 0,
      dst_port: port && portDir !== 'src' ? Math.trunc(port) : 0,
      mark: $('#inpMark').value.trim(),
      sample: daemon ? S.dsample : S.sample,
      sample_by: $('#selSampleBy').value || 'pkt',
      duration_sec: daemon ? 0 : S.duration,
      capture_hdr: (daemon ? $('#chkDCapHdr') : $('#chkCapHdr')).checked ? 96 : 0,
      profile_sendmsg: !daemon && $('#chkSendmsg').checked,
      enable_plugins: $('#chkPlugins').checked,
      allow_partial: $('#chkPartial').checked,
      trigger: daemon ? `sojourn_us>${Math.round(thrMs * 1000)}` : '',
      pre_window_sec: daemon ? Math.max(0, Math.trunc(toNum($('#inpPre').value) || 0)) : 0,
      post_window_sec: daemon ? Math.max(0, Math.trunc(toNum($('#inpPost').value) || 0)) : 0,
    };
  }
  async function startCapture() {
    const req = buildCaptureReq();
    const btn = $('#btnStart');
    btn.disabled = true;
    btn.querySelector('span').textContent = '正在启动…';
    try {
      const r = await api('/api/capture/start', { body: req, timeout: 60000 });
      beginCaptureUI({ id: r.capture_id, mode: req.mode, duration: req.duration_sec, dev: req.dev, startedAt: Date.now() });
      toast(req.mode === 'daemon' ? '后台蹲守已启动：卡顿时将自动落盘' : `采集已开始（${req.duration_sec}s）：请现在复现问题`, 'ok');
    } catch (e) {
      toast('启动采集失败：' + e.message, 'bad');
    } finally {
      btn.querySelector('span').textContent = '开始一键采集';
      updateStartBtn();
    }
  }
  function beginCaptureUI(cap) {
    S.capturing = true; S.stopping = false; S.cap = cap; S.lastStatus = null;
    $('#runPanel').hidden = false;
    $('#btnFlush').hidden = cap.mode !== 'daemon';
    $('#runTitle').textContent = cap.mode === 'daemon' ? '后台蹲守中 · 等待卡顿触发' : '复现抓包中 · 请现在复现问题';
    $('#runProgress').parentElement.classList.toggle('indeterminate', cap.mode === 'daemon' || !cap.duration);
    $('#runLog').textContent = '等待设备端日志…';
    $('#btnStop').disabled = false;
    $('#btnStop').querySelector('span').textContent = '停止并拉回分析';
    $('#selDevice').disabled = true; $('#selIface').disabled = true;
    updateStartBtn();
    clearInterval(S.pollTimer); clearInterval(S.tickTimer);
    S.pollTimer = setInterval(pollStatus, 1000);
    S.tickTimer = setInterval(tick, 500);
    tick();
  }
  function endCaptureUI() {
    S.capturing = false; S.stopping = false;
    clearInterval(S.pollTimer); clearInterval(S.tickTimer);
    $('#runPanel').hidden = true;
    $('#selDevice').disabled = false; $('#selIface').disabled = !S.serial;
    updateStartBtn();
  }
  function elapsedSec() {
    if (!S.cap) return 0;
    const st = S.lastStatus;
    const local = (Date.now() - S.cap.startedAt) / 1000;
    const srv = st && toNum(st.elapsed_sec);
    return srv !== null && srv !== undefined ? Math.max(srv, local - 2) : local;
  }
  function tick() {
    if (!S.capturing || !S.cap) return;
    const el = elapsedSec();
    const dur = S.cap.duration;
    $('#runTimer').textContent = dur && S.cap.mode !== 'daemon' ? `${fmtClock(el)} / ${fmtClock(dur)}` : fmtClock(el);
    if (dur && S.cap.mode !== 'daemon') $('#runProgress').style.width = clamp(el / dur * 100, 0, 100) + '%';
    const ph = S.lastStatus && S.lastStatus.phase;
    if (!S.stopping && S.cap.mode !== 'daemon' && dur && el >= dur + 4 && (!ph || ph === 'running')) {
      stopCapture(true);
    }
  }
  async function pollStatus() {
    if (!S.capturing) return;
    try {
      const st = await api('/api/capture/status', { timeout: 8000 });
      S.lastStatus = st;
      const lines = arr(st.log_lines).map(String);
      if (lines.length) {
        const log = $('#runLog');
        const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
        log.textContent = lines.slice(-40).join('\n');
        if (atBottom) log.scrollTop = log.scrollHeight;
      }
      if (st.phase === 'stopping') $('#runTitle').textContent = '采集完成 · 正在停止设备端探针…';
      else if (st.phase === 'pulling') $('#runTitle').textContent = '正在从手机拉回采集数据…';
      else if (st.phase === 'reconstructing') $('#runTitle').textContent = '正在重建单包路径与统计…';
      if (st.error) $('#runTitle').textContent = '设备端报告错误：' + String(st.error).slice(0, 80);
      if (!st.active && !S.stopping) {
        if (st.last_session_id && (!S.cap || !S.cap.id || st.capture_id === S.cap.id || !st.capture_id)) {
          if (st.session_path) S.sessionPaths[st.last_session_id] = st.session_path;
          endCaptureUI();
          toast('采集完成，已自动拉回并完成重建', 'ok');
          showSession(st.last_session_id);
          loadSessions();
        } else if (st.phase === 'error' || st.error) {
          endCaptureUI();
          toast('采集结束时出错：' + (st.error || '未知错误'), 'bad');
        } else {
          stopCapture(true);
        }
      }
    } catch (_) { /* transient */ }
  }
  async function stopCapture(auto) {
    if (S.stopping) return;
    S.stopping = true;
    const btn = $('#btnStop');
    btn.disabled = true;
    btn.querySelector('span').textContent = '正在拉回数据并重建路径…';
    $('#runTitle').textContent = auto ? '采集完成 · 正在从手机拉回数据…' : '正在停止并从手机拉回数据…';
    $('#runProgress').parentElement.classList.add('indeterminate');
    try {
      const r = await api('/api/capture/stop', { body: {}, timeout: 300000 });
      endCaptureUI();
      if (r.session_id) {
        if (r.session_path) S.sessionPaths[r.session_id] = r.session_path;
        toast(`已拉回并完成重建：${baseName(r.session_path) || r.session_id}`, 'ok');
        showSession(r.session_id, r.overview && typeof r.overview === 'object' ? r.overview : null);
      } else {
        toast('采集已停止，但未生成会话（可能没有命中任何包）', 'warn');
      }
      loadSessions();
    } catch (e) {
      toast('停止/拉回失败：' + e.message, 'bad');
      S.stopping = false;
      btn.disabled = false;
      btn.querySelector('span').textContent = '重试：停止并拉回分析';
      try {
        const st = await api('/api/capture/status', { timeout: 8000 });
        if (!st.active) { endCaptureUI(); if (st.last_session_id) showSession(st.last_session_id); }
      } catch (_) { /* ignore */ }
    }
  }
  async function flushCapture() {
    const b = $('#btnFlush');
    b.disabled = true;
    try {
      await api('/api/capture/flush', { body: {}, timeout: 15000 });
      toast('已发送 SIGUSR1：设备端正在把内存环落盘', 'ok');
    } catch (e) {
      toast('落盘快照失败：' + e.message, 'bad');
    } finally {
      setTimeout(() => { b.disabled = false; }, 1500);
    }
  }
  async function resumeCaptureIfActive() {
    try {
      const st = await api('/api/capture/status', { timeout: 8000 });
      if (st && st.active) {
        if (st.serial && !S.serial) S.serial = st.serial;
        const es = toNum(st.elapsed_sec) || 0;
        beginCaptureUI({ id: st.capture_id, mode: st.mode || 'oneshot', duration: st.mode === 'daemon' ? 0 : 0, dev: st.dev, startedAt: Date.now() - es * 1000 });
      }
    } catch (_) { /* ignore */ }
  }

  /* =====================================================================
   * 7. Sessions (history / open folder)
   * ===================================================================== */
  async function loadSessions() {
    const list = $('#historyList');
    try {
      const d = await api('/api/sessions', { timeout: 20000 });
      S.sessions = arr(d.sessions).filter((x) => x && (x.id || x.path));
      for (const s of S.sessions) { if (s.id && s.path) S.sessionPaths[s.id] = s.path; }
      S.sessions.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
      renderHistory();
      syncSessionPathUI();
    } catch (e) {
      list.innerHTML = `<div class="empty-mini">读取失败：${esc(e.message)}</div>`;
    }
  }
  function renderHistory() {
    const list = $('#historyList');
    if (!S.sessions.length) { list.innerHTML = '<div class="empty-mini">暂无会话 · 完成一次采集后会出现在这里</div>'; return; }
    list.innerHTML = S.sessions.map((s, i) => `
      <button class="hist-item" data-i="${i}" title="${esc(s.path || '')}">
        <span class="t">${esc(s.name || baseName(s.path) || s.id)}${s.id === S.sessionId ? ' <span class="badge">当前</span>' : ''}</span>
        <span class="m"><span>${esc(fmtTime(s.created_at) || '')}</span>${s.dev ? `<span>${esc(s.dev)}</span>` : ''}${s.scope ? `<span>${esc(s.scope)}</span>` : ''}${s.sample_count !== undefined && s.sample_count !== null ? `<span class="num">${esc(fmtInt(s.sample_count))} 样本</span>` : ''}</span>
      </button>`).join('');
  }
  function toggleHistory(force) {
    const m = $('#historyMenu');
    const show = force === undefined ? m.hidden : force;
    m.hidden = !show;
    $('#btnHistory').setAttribute('aria-expanded', String(show));
    if (show) loadSessions();
  }
  async function openFolder() {
    const b = $('#btnOpenFolder');
    b.disabled = true;
    try {
      const r = await api('/api/dialog/pick-folder', { body: {}, timeout: 0 });
      if (!r || !r.path) return;
      const o = await api('/api/sessions/open', { body: { path: r.path }, timeout: 180000 });
      if (!o.session_id) throw new Error('该目录不是有效的 pktpath 会话（需包含 manifest.json 与 block_*.pktb）');
      S.sessionPaths[o.session_id] = o.session_path || o.path || r.path;
      toast('已打开会话：' + baseName(r.path), 'ok');
      showSession(o.session_id, o.overview && typeof o.overview === 'object' ? o.overview : null);
      loadSessions();
    } catch (e) {
      if (!/cancel/i.test(e.message)) toast('打开会话失败：' + e.message, 'bad');
    } finally {
      b.disabled = false;
    }
  }

  /* =====================================================================
   * 8. Session overview -> KPIs, charts, table
   * ===================================================================== */
  async function showSession(id, overview) {
    if (!id) return;
    closeDrawer();
    let ov = overview;
    if (!ov) {
      $('#emptyState').hidden = true;
      $('#sessionView').hidden = false;
      $('#kpis').innerHTML = '<div class="kpi" style="grid-column:1/-1"><div class="drawer-loading"><span class="spinner"></span> 正在加载会话…</div></div>';
      try {
        ov = await api('/api/session/overview?' + qs({ id }), { timeout: 180000 });
      } catch (e) {
        toast('加载会话失败：' + e.message, 'bad');
        if (!S.overview) { $('#sessionView').hidden = true; $('#emptyState').hidden = false; }
        else renderSession();
        return;
      }
    }
    S.sessionId = id;
    S.overview = obj(ov);
    if (S.overview.session_path) S.sessionPaths[id] = String(S.overview.session_path);
    else if (S.overview.path) S.sessionPaths[id] = String(S.overview.path);
    hideSavedBar();
    S.filter = { q: '', uid: '', seq: '', status: 'all', prefix: null };
    S.sort = { k: 'max_sojourn_us', dir: -1 };
    S.shown = 300;
    $('#tblSearch').value = ''; $('#tblSeq').value = '';
    setSeg($('#segStatus'), 'all');
    prepareSession();
    renderSession();
    renderHistory();
  }
  function normSample(s) {
    s = obj(s);
    const o = Object.assign({}, s);
    for (const k of ['sample_id', 'uid', 'tgid', 'enqueue_tid', 'tcp_seq', 'pkt_len', 'max_sojourn_us', 'total_us', 'branch_count']) {
      const v = toNum(s[k]);
      o[k] = v;
    }
    o.complete = s.complete === true || s.complete === 1 || s.complete === 'true';
    o.requeued = s.requeued === true || toNum(s.requeued) > 0;
    o._sigs = String(s.path_sig || '').split(/\s*(?:\n|\|\||;|\s\|\s)\s*/).filter(Boolean).map(splitSig);
    return o;
  }
  function splitSig(sig) { return String(sig || '').split(/\s*(?:->|→)\s*/).map((t) => t.trim()).filter(Boolean); }
  function qKey(kind, handle) {
    return String(kind || '').toLowerCase().replace(/[^a-z0-9_]/g, '') + '|' + String(handle === undefined || handle === null ? '' : handle).trim().toLowerCase().replace(/\s+/g, '').replace(/:0+$/, ':');
  }
  function parseClassToken(tok) {
    const m = /^CLASS:([0-9a-fA-F]*:[0-9a-fA-F]*)$/i.exec(String(tok || '').trim());
    return m ? { classid: m[1].toLowerCase() } : null;
  }
  function parseQueueToken(tok) {
    const s = String(tok || '').trim();
    if (/^CLASS:/i.test(s)) return null;
    const ma = /^(?:[^\s]+\s+)?([A-Za-z][A-Za-z0-9_]*)\s*@\s*([0-9a-fA-F]*:[0-9a-fA-F]*)\s*(?:\(.*\))?$/.exec(s);
    if (ma) return { kind: ma[1], handle: '@' + ma[2].toLowerCase(), atParent: ma[2].toLowerCase() };
    const m = /^([A-Za-z][A-Za-z0-9_]*)[\s:]+([0-9a-fA-F]*:[0-9a-fA-F]*)\s*(?:\(.*\))?$/.exec(s);
    return m ? { kind: m[1], handle: m[2].toLowerCase() } : null;
  }
  function prepareSession() {
    const ov = S.overview;
    const st = obj(ov.stats);
    S.samples = arr(ov.samples).map(normSample);
    S.queues = arr(st.queues).map(obj);
    S.qIndex = {};
    for (const q of S.queues) {
      const keys = [];
      const hStr = fmtHandle(q.handle);
      const pStr = q.parent !== undefined && q.parent !== null ? fmtHandle(q.parent) : '';
      if ((hStr === '0:' || q.handle === 0) && pStr && pStr !== '0:' && pStr !== 'root' && !/^ffff:/i.test(pStr)) {
        keys.push(qKey(q.kind, '@' + pStr));
        keys.push(qKey('qdisc', '@' + pStr));
      } else if (q.kind !== undefined || q.handle !== undefined) {
        keys.push(qKey(q.kind, hStr));
      }
      if (q.visit_kind === 'requeue_gso' || q.kind === 'requeue_gso') keys.push('requeue_gso|');
      if (q.visit_kind === 'requeue_bad_txq' || q.kind === 'requeue_bad_txq') keys.push('requeue_bad_txq|');
      const pl = parseQueueToken(q.label);
      if (pl) keys.push(qKey(pl.kind, pl.handle));
      for (const k of keys) {
        const prev = S.qIndex[k];
        if (!prev || (toNum(q.paired_n) || 0) > (toNum(prev.paired_n) || 0)) S.qIndex[k] = q;
      }
    }
    S.classIndex = {};
    for (const ep of arr(obj(ov.dict).topology_epochs)) {
      for (const c of arr(obj(ep).classes)) {
        const ch = fmtHandle(c && c.handle);
        if (ch && ch !== '—') S.classIndex[ch.toLowerCase()] = c;
      }
    }
    for (const c of arr(S.inspect && S.inspect.classes)) {
      const ch = fmtHandle(c && c.handle);
      if (ch && ch !== '—' && !S.classIndex[ch.toLowerCase()]) S.classIndex[ch.toLowerCase()] = c;
    }
    const soj = S.samples.map((s) => s.max_sojourn_us).filter((v) => isNum(v) && v > 0).sort((a, b) => a - b);
    S.maxSoj = soj.length ? soj[soj.length - 1] : 0;
    S.slowThr = soj.length ? percentile(soj, 0.9) : 0;
  }
  function queueLabel(q) {
    if (q.label) return String(q.label);
    const h = fmtHandle(q.handle);
    const p = q.parent !== undefined && q.parent !== null ? fmtHandle(q.parent) : '';
    if ((h === '0:' || q.handle === 0) && p && p !== '0:' && p !== 'root' && !/^ffff:/i.test(p)) {
      return `${String(q.kind || 'pfifo').toUpperCase()} @ ${p}`;
    }
    return `${String(q.kind || 'queue').toUpperCase()} ${h}`;
  }
  function shortQueueLabel(q) {
    let s = queueLabel(q).replace(/\s*\([^)]*gen=[^)]*\)\s*$/, '').trim();
    const dev = obj(S.overview && S.overview.manifest).dev;
    if (dev && s.toLowerCase().startsWith(String(dev).toLowerCase() + ' ')) s = s.slice(String(dev).length + 1).trim();
    return s;
  }
  function currentSessionPath() {
    if (!S.sessionId) return '';
    return String(pick(S.overview, 'session_path', 'path') || (S.sessions.find((x) => x.id === S.sessionId) || {}).path || S.sessionPaths[S.sessionId] || '');
  }
  function syncSessionPathUI() {
    const btn = $('#btnRevealSession');
    if (!btn) return;
    const sp = currentSessionPath();
    btn.title = sp ? `在资源管理器中打开会话目录：\n${sp}` : '在资源管理器中打开当前会话目录';
    btn.disabled = !sp && !DEMO;
  }
  function renderSession() {
    $('#emptyState').hidden = true;
    $('#sessionView').hidden = false;
    const ov = S.overview;
    const m = obj(ov.manifest);
    const sess = S.sessions.find((x) => x.id === S.sessionId) || {};
    const sp = currentSessionPath();
    $('#sessTitle').textContent = sess.name || baseName(sp) || m.session_name || `会话 ${S.sessionId}`;
    $('#sessTitle').title = sp || '';
    syncSessionPathUI();
    const cal = arr(m.calibrations)[0];
    const started = cal && toNum(cal.realtime_ns) ? fmtTime(cal.realtime_ns) : fmtTime(sess.created_at || m.created_at);
    const chips = [];
    if (started) chips.push(['muted', started]);
    if (m.dev || sess.dev) chips.push(['accent', '网卡 ' + (m.dev || sess.dev)]);
    if (m.scope || sess.scope) chips.push(['', m.scope || sess.scope]);
    if (m.mode) chips.push(['', m.mode === 'daemon' ? '后台蹲守' : '复现抓包']);
    if (m.sample_rate) chips.push(['', '抽样 ' + m.sample_rate + (m.sample_by === 'flow' ? ' (按流)' : '')]);
    if (m.kernel_release) chips.push(['', 'kernel ' + String(m.kernel_release).split('-')[0]]);
    if (m.partial_coverage) chips.push(['warn', '部分探针覆盖']);
    $('#sessMeta').innerHTML = chips.map(([c, t]) => c === 'warn'
      ? `<span class="badge badge-warn">${esc(t)}</span>`
      : `<span class="chip ${c === 'accent' ? 'chip-accent' : ''}">${esc(t)}</span>`).join('');
    renderKPIs();
    renderCharts();
    renderUidFilter();
    renderTable();
    if (window.PktPathStudio && typeof window.PktPathStudio._onSessionRendered === 'function') {
      window.PktPathStudio._onSessionRendered(S.overview, S.sessionId);
    }
  }

  /* ---- KPI strip ---- */
  function normAlerts(x) {
    if (x === null || x === undefined || x === false) return [];
    if (Array.isArray(x)) {
      return x.map((a) => {
        if (a && typeof a === 'object') {
          const sev = String(a.severity || 'warn').toLowerCase();
          const k = a.kind || a.type || a.name || '告警';
          const d = a.detail || a.message || a.desc || (a.count !== undefined ? 'count=' + a.count : '');
          return { sev, text: d ? `${k}: ${d}` : String(k), short: d || String(k) };
        }
        return { sev: 'warn', text: String(a), short: String(a) };
      }).filter((a) => a.text);
    }
    if (isNum(x)) return x > 0 ? [{ sev: 'warn', text: `${x} 条质量告警`, short: `${x} 条质量告警` }] : [];
    if (typeof x === 'object') {
      return Object.keys(x).filter((k) => x[k] && toNum(x[k]) !== 0).map((k) => {
        const s = `${k} = ${typeof x[k] === 'object' ? JSON.stringify(x[k]) : x[k]}`;
        return { sev: 'warn', text: s, short: s };
      });
    }
    return String(x) ? [{ sev: 'warn', text: String(x), short: String(x) }] : [];
  }
  function renderKPIs() {
    const ov = S.overview, st = obj(ov.stats), m = obj(ov.manifest);
    const adm = Object.assign({}, obj(m.admissions), obj(st.admissions));
    const nSamples = S.samples.length;
    const cards = [];

    // 1. samples & admission funnel
    const order = ['matched', 'selected', 'created', 'rejected', 'filter_unknown'];
    const keys = order.filter((k) => k in adm).concat(Object.keys(adm).filter((k) => !order.includes(k)));
    const funnel = keys.length
      ? `<table>${keys.map((k) => `<tr><td>${esc(ADMISSION_ZH[k] || k)}</td><td class="r">${esc(fmtInt(adm[k]))}</td></tr>`).join('')}<tr><td>可分析样本</td><td class="r">${esc(fmtInt(nSamples))}</td></tr></table>`
      : '无准入计数';
    const subParts = [];
    if (adm.matched !== undefined) subParts.push(`命中 ${fmtInt(adm.matched)}`);
    if (adm.selected !== undefined) subParts.push(`入选 ${fmtInt(adm.selected)}`);
    if (toNum(adm.rejected)) subParts.push(`拒绝 ${fmtInt(adm.rejected)}`);
    cards.push({ cls: '', label: '入选样本数', tip: `<div class="tt-title">准入漏斗</div>${funnel}`, value: fmtInt(nSamples), unit: '个', sub: subParts.join(' · ') || '—' });

    // 2. complete branch rate
    const br = obj(st.branches);
    let total = toNum(br.total), comp = toNum(br.complete);
    if (total === null) { total = S.samples.reduce((a, s) => a + (s.branch_count || 1), 0); comp = null; }
    if (comp === null) comp = S.samples.filter((s) => s.complete).length, total = total || nSamples;
    const rate = total ? comp / total : null;
    cards.push({
      cls: rate === null ? '' : rate >= 0.99 ? 'ok' : rate >= 0.9 ? 'warn' : 'bad', label: '完整支路率',
      tip: `<div class="tt-title">支路完整性</div>一个包被 clone/分段后会产生多条支路；完整 = 从入口到终点每一跳都有证据。<table><tr><td>总支路</td><td class="r">${esc(fmtInt(total))}</td></tr><tr><td>完整</td><td class="r">${esc(fmtInt(comp))}</td></tr><tr><td>不完整</td><td class="r">${esc(fmtInt(br.incomplete))}</td></tr><tr><td>未知尾部</td><td class="r">${esc(fmtInt(br.unknown))}</td></tr></table>`,
      value: fmtPct(rate), unit: '', sub: `完整 ${fmtInt(comp)} / ${fmtInt(total)}${toNum(br.unknown) ? ' · 未知 ' + fmtInt(br.unknown) : ''}`,
    });

    // 3. slowest queue p95/p99
    let slow = null;
    for (const q of S.queues) { const v = toNum(q.p99_us) ?? toNum(q.p95_us); if (v !== null && (!slow || v > (toNum(slow.p99_us) ?? toNum(slow.p95_us)))) slow = q; }
    if (slow) {
      const p95 = usParts(slow.p95_us), p99 = usParts(slow.p99_us);
      const sameUnit = p95[1] === p99[1];
      cards.push({
        cls: (toNum(slow.p99_us) || 0) >= 20000 ? 'bad' : (toNum(slow.p99_us) || 0) >= 2000 ? 'warn' : 'ok', label: '最慢队列 p95 / p99',
        tip: `<div class="tt-title">${esc(queueLabel(slow))}</div><table><tr><td>p50</td><td class="r">${esc(fmtUs(slow.p50_us))}</td></tr><tr><td>p95</td><td class="r">${esc(fmtUs(slow.p95_us))}</td></tr><tr><td>p99</td><td class="r">${esc(fmtUs(slow.p99_us))}</td></tr><tr><td>max</td><td class="r">${esc(fmtUs(slow.max_us))}</td></tr><tr><td>配对样本 n</td><td class="r">${esc(fmtInt(slow.paired_n))}</td></tr></table>`,
        valueHtml: sameUnit ? `${esc(p95[0])} / ${esc(p99[0])}<small>${esc(p99[1])}</small>` : `${esc(p95[0])}<small>${esc(p95[1])}</small> / ${esc(p99[0])}<small>${esc(p99[1])}</small>`,
        sub: `${shortQueueLabel(slow)} · n=${fmtInt(slow.paired_n)}`,
      });
    } else {
      cards.push({ cls: '', label: '最慢队列 p95 / p99', value: '—', unit: '', sub: '本会话无队列驻留数据', tip: '未观测到 qdisc 入队/出队配对（可能为 noqueue 直通或探针缺失）' });
    }

    // 4. requeue / reorder
    const rq = toNum(st.requeue_count) ?? S.samples.filter((s) => s.requeued).length;
    const ro = toNum(st.reorder_count) ?? 0;
    cards.push({
      cls: rq || ro ? 'violet' : 'ok', label: 'Requeue / 乱序',
      tip: '<div class="tt-title">重新排队 / 乱序</div>Requeue：驱动忙 (NETDEV_TX_BUSY) 或 GSO 拆分后被放回队列重发。<br>乱序：同一条流中后入队的包先离开队列。',
      valueHtml: `${esc(fmtInt(rq))} <small>/</small> ${esc(fmtInt(ro))}`, sub: `重新排队 ${fmtInt(rq)} 次 · 乱序 ${fmtInt(ro)} 次`,
    });

    // 5. quality health
    const alerts = normAlerts(st.quality_alerts);
    if (st.unclean_tail && !alerts.some((a) => /unclean_tail/i.test(a.text))) {
      alerts.unshift({ sev: 'error', text: 'UNCLEAN_TAIL: 采集非正常结束，尾部数据块不完整（已安全回放有效块）', short: '尾部不完整（已回放有效块）' });
    }
    const hardAlerts = alerts.filter((a) => a.sev !== 'info');
    const hasErr = hardAlerts.some((a) => a.sev === 'error');
    const ok = !hardAlerts.length;
    cards.push({
      cls: ok ? 'ok' : hasErr ? 'bad' : 'warn', label: '质量健康度',
      tip: !alerts.length ? '<div class="tt-title">数据质量良好</div>无 ringbuf 丢事件、无探针漏报 (missed)、无身份冲突。'
        : `<div class="tt-title">${ok ? '0 漏报（附提示）' : hardAlerts.length + ' 项质量告警'}</div>${alerts.slice(0, 12).map((a) => '• ' + esc(a.text)).join('<br>')}`,
      valueHtml: ok ? '0 漏报 <small>✔</small>' : `${hardAlerts.length} <small>项${hasErr ? '异常' : '黄警'}</small>`,
      sub: ok ? (alerts.length ? alerts[0].short : '0 missed · 0 丢事件') : hardAlerts[0].short,
    });

    $('#kpis').innerHTML = cards.map((c) => `
      <div class="kpi ${c.cls}"${c.tip ? tipAttr(c.tip) : ''}>
        <div class="kpi-label">${esc(c.label)}${c.tip ? '<span class="q">?</span>' : ''}</div>
        <div class="kpi-value">${c.valueHtml || esc(c.value) + (c.unit ? `<small>${esc(c.unit)}</small>` : '')}</div>
        <div class="kpi-sub" title="${esc(c.sub)}">${esc(c.sub)}</div>
      </div>`).join('');
  }

  /* ---- charts ---- */
  function renderCharts() {
    if (!S.overview || $('#sessionView').hidden) return;
    renderFlow();
    renderLatency();
  }
  function pathGroups() {
    const st = obj(S.overview.stats);
    let groups = arr(st.paths).map(obj).filter((p) => p.path_sig);
    if (!groups.length) {
      const m = new Map();
      for (const s of S.samples) {
        for (const toks of s._sigs) {
          const sig = toks.join(' -> ');
          const g = m.get(sig) || { path_sig: sig, count: 0, complete_count: 0 };
          g.count++; if (s.complete) g.complete_count++;
          m.set(sig, g);
        }
      }
      groups = Array.from(m.values());
    }
    return groups.map((g) => Object.assign({}, g, { _toks: splitSig(g.path_sig), count: toNum(g.count) || 0 }));
  }
  function tokenView(tok, isLast) {
    const t = String(tok);
    const tu = t.toUpperCase();
    if (tu === 'REQUEUE_GSO' || tu === 'REQUEUE_BAD_TXQ') {
      return { t1: tu === 'REQUEUE_GSO' ? 'REQUEUE' : 'BAD_TXQ', t2: tu === 'REQUEUE_GSO' ? 'gso_skb' : 'skb_bad_txq', type: 'queue', q: { kind: tu.toLowerCase(), handle: '' } };
    }
    const ct = parseClassToken(t);
    if (ct && !isLast) {
      const ci = S.classIndex[ct.classid];
      const rate = ci ? fmtRateRange(ci.rate_bps, ci.ceil_bps) : '';
      const pr = ci && String(ci.kind || '').toLowerCase() === 'htb' && ci.prio !== undefined ? `p${ci.prio}` : '';
      return { t1: `CLASS ${ct.classid}`, t2: [rate, pr].filter(Boolean).join(' · ') || 'TC 子类', type: 'tclass', classid: ct.classid, ci };
    }
    let m = /^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$/.exec(t);
    if (m) return { t1: m[1], t2: m[2], type: m[1].toUpperCase() === 'ENTRY' ? 'entry' : 'step' };
    const q = parseQueueToken(t);
    if (q && !isLast) return { t1: q.kind.toUpperCase(), t2: q.atParent ? `@ ${q.atParent}` : q.handle, type: 'queue', q };
    if (isLast || ENDPOINT_ZH[tu]) return { t1: t, t2: ENDPOINT_ZH[tu] || '终点', type: 'end' };
    return { t1: t.replace(/_/g, ' '), t2: '', type: 'step' };
  }
  function renderFlow() {
    const wrap = $('#flowWrap');
    const groups = pathGroups().filter((g) => g._toks.length);
    if (!groups.length) { wrap.innerHTML = '<div class="empty-mini">本会话没有可绘制的路径</div>'; return; }
    // build trie
    const root = { tok: '', children: new Map(), count: 0, depth: -1, prefix: [], groups: [] };
    for (const g of groups) {
      let n = root;
      n.count += g.count;
      g._toks.forEach((tok, i) => {
        let c = n.children.get(tok);
        if (!c) { c = { tok, children: new Map(), count: 0, depth: i, prefix: g._toks.slice(0, i + 1), groups: [], parent: n }; n.children.set(tok, c); }
        c.count += g.count;
        c.groups.push(g);
        if (i === g._toks.length - 1) c.terminal = true;
        n = c;
      });
    }
    // layout
    const NW = 100, NH = 38, COL = 132, ROW = 56, PADX = 12, PADY = 22;
    let row = 0, maxDepth = 0;
    const all = [];
    const place = (n) => {
      const kids = Array.from(n.children.values()).sort((a, b) => b.count - a.count);
      n.kids = kids;
      if (n !== root) { all.push(n); maxDepth = Math.max(maxDepth, n.depth); }
      if (!kids.length) { n.y = row++; return; }
      kids.forEach(place);
      n.y = (kids[0].y + kids[kids.length - 1].y) / 2;
    };
    place(root);
    const W = PADX * 2 + (maxDepth + 1) * COL - (COL - NW);
    const H = PADY * 2 + Math.max(1, row) * ROW - (ROW - NH);
    const X = (n) => PADX + n.depth * COL;
    const Y = (n) => PADY + n.y * ROW;
    const maxC = Math.max(1, root.count);
    const prefix = S.filter.prefix;
    const prefStr = prefix ? prefix.join('\u0001') : null;
    const inSel = (n) => !prefix || n.prefix.join('\u0001').startsWith(prefStr) || prefStr.startsWith(n.prefix.join('\u0001'));

    let edges = '', nodes = '';
    for (const n of all) {
      for (const c of n.kids) {
        const x1 = X(n) + NW, y1 = Y(n) + NH / 2, x2 = X(c), y2 = Y(c) + NH / 2, mx = (x1 + x2) / 2;
        const sw = (1.5 + 13 * c.count / maxC).toFixed(1);
        const tip = `<div class="tt-title">${esc(n.tok)} → ${esc(c.tok)}</div>${esc(fmtInt(c.count))} 个包 (${esc(fmtPct(c.count / maxC))})`;
        edges += `<path class="fl-edge ${prefix ? (inSel(c) ? 'hl' : 'dim') : ''}" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" stroke-width="${sw}" data-prefix="${esc(JSON.stringify(c.prefix))}"${tipAttr(tip)}/>`;
      }
    }
    // root -> first-level edges are implicit (first column nodes)
    for (const n of all) {
      const isLeaf = !n.kids.length;
      const v = tokenView(n.tok, isLeaf && n.terminal);
      let cls = 'fl-node';
      if (v.type === 'end') cls += ' end-' + endpointClass(n.tok);
      if (v.type === 'queue') cls += ' queue';
      if (v.type === 'tclass') cls += ' tclass';
      if (prefix && n.prefix.join('\u0001') === prefStr) cls += ' sel';
      else if (prefix && !inSel(n)) cls += ' dim';
      const x = X(n), y = Y(n);
      const t1 = v.t1.length > 13 ? v.t1.slice(0, 12) + '…' : v.t1;
      const t2 = String(v.t2 || '').length > 15 ? String(v.t2).slice(0, 14) + '…' : String(v.t2 || '');
      let tip = `<div class="tt-title">${esc(n.tok)}</div>经过 ${esc(fmtInt(n.count))} 个包 (${esc(fmtPct(n.count / maxC))})`;
      let badge = '';
      if (v.type === 'tclass' && v.ci) {
        const ci = v.ci;
        const rr = fmtRateRange(ci.rate_bps, ci.ceil_bps);
        tip += `<table>${ci.kind ? `<tr><td>类型</td><td class="r">${esc(ci.kind)}</td></tr>` : ''}${rr ? `<tr><td>速率/上限</td><td class="r">${esc(rr)}</td></tr>` : ''}${ci.prio !== undefined ? `<tr><td>优先级 prio</td><td class="r">${esc(ci.prio)}</td></tr>` : ''}</table>`;
      }
      if (v.type === 'queue') {
        const qs_ = S.qIndex[qKey(v.q.kind, v.q.handle)] || (v.q.atParent ? S.qIndex[qKey('qdisc', '@' + v.q.atParent)] : null);
        if (qs_) {
          const p95 = toNum(qs_.p95_us);
          tip += `<table><tr><td>驻留 p50</td><td class="r">${esc(fmtUs(qs_.p50_us))}</td></tr><tr><td>驻留 p95</td><td class="r">${esc(fmtUs(qs_.p95_us))}</td></tr><tr><td>驻留 p99</td><td class="r">${esc(fmtUs(qs_.p99_us))}</td></tr><tr><td>配对 n</td><td class="r">${esc(fmtInt(qs_.paired_n))}</td></tr>${qs_.class_rate ? `<tr><td>子类速率</td><td class="r">${esc(qs_.class_rate)}</td></tr>` : ''}${toNum(qs_.drop_count) ? `<tr><td>丢包</td><td class="r">${esc(fmtInt(qs_.drop_count))}</td></tr>` : ''}</table>`;
          if (p95 !== null) {
            const txt = fmtUs(p95);
            const bw = Math.max(34, txt.length * 6 + 8);
            const heat = p95 >= 10000 ? 'hot' : p95 < 1000 ? 'cool' : '';
            badge = `<g class="fl-badge ${heat}" transform="translate(${x + NW - bw + 6},${y - 9})"><rect width="${bw}" height="15" rx="7.5"/><text x="${bw / 2}" y="11" text-anchor="middle">${esc(txt)}</text></g>`;
          }
        }
      }
      if (v.type === 'end') {
        const pg = n.groups.filter((g) => g._toks.length === n.prefix.length);
        if (pg.length === 1) {
          const g = pg[0];
          tip += `<table><tr><td>完整</td><td class="r">${esc(fmtInt(g.complete_count))}/${esc(fmtInt(g.count))}</td></tr>${g.p50_us !== undefined ? `<tr><td>全程 p50</td><td class="r">${esc(fmtUs(g.p50_us))}</td></tr><tr><td>全程 p95</td><td class="r">${esc(fmtUs(g.p95_us))}</td></tr><tr><td>全程 p99</td><td class="r">${esc(fmtUs(g.p99_us))}</td></tr>` : ''}</table>`;
        }
      }
      tip += '<br><span style="opacity:.7">点击：只看经过此节点的包</span>';
      nodes += `<g class="${cls}" data-prefix="${esc(JSON.stringify(n.prefix))}"${tipAttr(tip)}>
        <rect class="box" x="${x}" y="${y}" width="${NW}" height="${NH}" rx="8"/>
        <text class="t1" x="${x + NW / 2}" y="${y + (t2 ? 16 : 23)}" text-anchor="middle">${esc(t1)}</text>
        ${t2 ? `<text class="t2" x="${x + NW / 2}" y="${y + 30}" text-anchor="middle">${esc(t2)}</text>` : ''}
        <text class="fl-count" x="${x + 3}" y="${y + NH + 11}">n=${esc(fmtInt(n.count))}</text>
        ${badge}</g>`;
    }
    const flowStyle = maxDepth + 1 <= 12 ? 'width:100%;height:auto;' : `width:${W}px;height:${H + 6}px;`;
    wrap.innerHTML = `<svg style="${flowStyle}" viewBox="0 0 ${W} ${H + 6}" role="img" aria-label="队列路径流向图">${edges}${nodes}</svg>`;
  }
  function renderLatency() {
    const wrap = $('#latWrap');
    const qs_ = S.queues.filter((q) => toNum(q.p50_us) !== null || toNum(q.p95_us) !== null || toNum(q.p99_us) !== null);
    if (!qs_.length) { wrap.innerHTML = '<div class="empty-mini">没有队列驻留耗时数据</div>'; return; }
    qs_.sort((a, b) => (toNum(b.p99_us) ?? toNum(b.p95_us) ?? 0) - (toNum(a.p99_us) ?? toNum(a.p95_us) ?? 0));
    const W = Math.max(360, (wrap.clientWidth || 480) - 4);
    const LW = 132, RW = 96, ROW = 34, TOP = 18;
    const BW = W - LW - RW - 8;
    const vmax = Math.max(1, ...qs_.map((q) => Math.max(toNum(q.p99_us) || 0, toNum(q.p95_us) || 0, toNum(q.p50_us) || 0)));
    const H = TOP + qs_.length * ROW + 6;
    const sx = (v) => Math.max(v > 0 ? 2 : 0, (toNum(v) || 0) / vmax * BW);
    let g = '';
    for (let i = 0; i <= 4; i++) {
      const x = LW + BW * i / 4;
      g += `<line class="lat-grid" x1="${x}" x2="${x}" y1="${TOP - 4}" y2="${H - 4}"/>`;
      if (BW >= 340 || i === 0 || i === 4 || (i === 2 && BW >= 220)) {
        const lbl = i === 0 ? '0' : fmtUs(vmax * i / 4);
        g += `<text class="lat-axis" x="${x}" y="${TOP - 7}" text-anchor="${i === 0 ? 'start' : i === 4 ? 'end' : 'middle'}">${esc(lbl)}</text>`;
      }
    }
    qs_.forEach((q, i) => {
      const y = TOP + i * ROW;
      const fullLbl = queueLabel(q);
      const lbl = shortQueueLabel(q);
      const l = lbl.length > 18 ? lbl.slice(0, 17) + '…' : lbl;
      const sub = [`n=${fmtInt(q.paired_n)}`, q.class_rate || (q.queue_gen ? `gen ${q.queue_gen}` : ''), toNum(q.drop_count) ? `丢 ${fmtInt(q.drop_count)}` : ''].filter(Boolean).join(' · ');
      const tip = `<div class="tt-title">${esc(fullLbl)}</div><table><tr><td>p50</td><td class="r">${esc(fmtUs(q.p50_us))}</td></tr><tr><td>p95</td><td class="r">${esc(fmtUs(q.p95_us))}</td></tr><tr><td>p99</td><td class="r">${esc(fmtUs(q.p99_us))}</td></tr><tr><td>max</td><td class="r">${esc(fmtUs(q.max_us))}</td></tr><tr><td>配对样本 n</td><td class="r">${esc(fmtInt(q.paired_n))}</td></tr>${q.kind ? `<tr><td>类型</td><td class="r">${esc(q.kind)}</td></tr>` : ''}${q.class_rate ? `<tr><td>子类速率</td><td class="r">${esc(q.class_rate)}</td></tr>` : ''}${q.class_prio !== undefined && q.class_prio !== null ? `<tr><td>子类 prio</td><td class="r">${esc(q.class_prio)}</td></tr>` : ''}${toNum(q.drop_count) ? `<tr><td>丢包</td><td class="r">${esc(fmtInt(q.drop_count))}</td></tr>` : ''}</table>`;
      g += `<g class="lat-row"${tipAttr(tip)}>
        <rect class="lat-bg" x="0" y="${y}" width="${W}" height="${ROW}" rx="4"/>
        <text class="lat-label" x="4" y="${y + 15}">${esc(l)}</text>
        <text class="lat-sub" x="4" y="${y + 28}">${esc(sub)}</text>
        <rect x="${LW}" y="${y + 9}" width="${sx(q.p99_us).toFixed(1)}" height="16" rx="3" fill="var(--p99)"/>
        <rect x="${LW}" y="${y + 9}" width="${sx(q.p95_us).toFixed(1)}" height="16" rx="3" fill="var(--p95)"/>
        <rect x="${LW}" y="${y + 9}" width="${sx(q.p50_us).toFixed(1)}" height="16" rx="3" fill="var(--p50)"/>
        <text class="lat-val" x="${W - 4}" y="${y + 15}" text-anchor="end">p95 ${esc(fmtUs(q.p95_us))}</text>
        <text class="lat-sub" x="${W - 4}" y="${y + 28}" text-anchor="end">p99 ${esc(fmtUs(q.p99_us))}</text>
      </g>`;
    });
    wrap.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="各队列驻留耗时对比">${g}</svg>`;
  }

  /* ---- sample table ---- */
  function appName(uid) {
    const p = S.uidMap[uid];
    if (p && p.length) return p.length > 1 ? `${p[0]} 等 ${p.length} 个` : p[0];
    if (uid === 0) return 'root';
    if (uid === 1000) return 'system';
    if (uid === 2000) return 'shell';
    return '';
  }
  function renderUidFilter() {
    const sel = $('#tblUid');
    const cnt = new Map();
    for (const s of S.samples) { const k = s.uid === null ? '' : String(s.uid); if (k !== '') cnt.set(k, (cnt.get(k) || 0) + 1); }
    const opts = Array.from(cnt.entries()).sort((a, b) => b[1] - a[1]);
    sel.innerHTML = '<option value="">全部 UID / 应用</option>' + opts.map(([uid, n]) => {
      const comm = (S.samples.find((s) => String(s.uid) === uid && s.comm) || {}).comm;
      const nm = appName(Number(uid)) || comm || '';
      return `<option value="${esc(uid)}">${esc(`uid ${uid}${nm ? ' · ' + nm : ''} (${n})`)}</option>`;
    }).join('');
    sel.value = S.filter.uid;
  }
  function isBad(s) { return !s.complete || s.requeued || ['bad', 'warn'].includes(endpointClass(s.endpoint)); }
  function isSlow(s) { return isNum(s.max_sojourn_us) && s.max_sojourn_us > 0 && s.max_sojourn_us >= S.slowThr; }
  function filteredSamples() {
    const f = S.filter;
    const q = f.q.trim().toLowerCase();
    const pf = f.prefix;
    return S.samples.filter((s) => {
      if (f.uid !== '' && String(s.uid) !== f.uid) return false;
      if (f.seq && !String(s.tcp_seq === null ? '' : s.tcp_seq).includes(f.seq.trim())) return false;
      if (f.status === 'slow' && !isSlow(s)) return false;
      if (f.status === 'bad' && !isBad(s)) return false;
      if (pf && !s._sigs.some((toks) => pf.every((t, i) => toks[i] === t))) return false;
      if (q) {
        const hay = [s.sample_id, s.comm, s.uid, appName(s.uid), s.src, s.dst, s.proto, s.endpoint, s.path_sig, s.tcp_seq].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }
  function cmp(a, b, k) {
    const va = a[k], vb = b[k];
    const na = va === null || va === undefined || va === '', nb = vb === null || vb === undefined || vb === '';
    if (na && nb) return 0;
    if (na) return 1;
    if (nb) return -1;
    if (typeof va === 'number' && typeof vb === 'number') return va - vb;
    if (typeof va === 'boolean' || typeof vb === 'boolean') return (va ? 1 : 0) - (vb ? 1 : 0);
    return String(va).localeCompare(String(vb), 'en', { numeric: true });
  }
  function completenessText(s) {
    const c = s.completeness;
    if (isNum(c)) return c <= 1 ? fmtPct(c) : c + '%';
    if (c && typeof c === 'string' && !/^(complete|incomplete|unknown)$/i.test(c)) return c;
    return '';
  }
  function completenessBadge(s) {
    const lc = String(s.completeness || '').toLowerCase();
    if (s.complete || lc === 'complete') return '<span class="badge badge-ok">完整</span>';
    if (lc === 'unknown') return '<span class="badge badge-muted" title="缺少漏报源可观测性或尾部未知">未知</span>';
    const cpl = completenessText(s);
    return `<span class="badge badge-warn"${cpl ? ` title="完整度 ${esc(cpl)}"` : ''}>不完整${cpl ? ' ' + esc(cpl) : ''}</span>`;
  }
  function renderTable() {
    if (!S.overview) return;
    const rows = filteredSamples();
    const { k, dir } = S.sort;
    rows.sort((a, b) => {
      const n = (k === 'max_sojourn_us' || k === 'total_us' || k === 'tcp_seq' || k === 'pkt_len' || k === 'branch_count' || k === 'sample_id' || k === 'uid')
        ? cmp(a, b, k) : cmp(a, b, k);
      if (n === 0) return cmp(a, b, 'sample_id');
      const na = a[k] === null || a[k] === undefined || a[k] === '', nb = b[k] === null || b[k] === undefined || b[k] === '';
      return na || nb ? n : n * dir;
    });
    $$('#sampleTable th').forEach((th) => {
      th.classList.toggle('sorted', th.dataset.k === k);
      th.classList.toggle('desc', th.dataset.k === k && dir < 0);
      th.classList.toggle('asc', th.dataset.k === k && dir > 0);
    });
    $('#tableCount').textContent = rows.length === S.samples.length ? fmtInt(rows.length) : `${fmtInt(rows.length)} / ${fmtInt(S.samples.length)}`;
    const chip = $('#pathChip');
    if (S.filter.prefix) {
      chip.hidden = false;
      chip.textContent = '路径：' + S.filter.prefix.join(' → ');
      chip.title = '点击清除路径筛选';
      $('#btnClearPath').hidden = false;
    } else { chip.hidden = true; $('#btnClearPath').hidden = true; }
    $('#segStatus button[data-v="slow"]').title = S.slowThr ? `最大排队耗时 ≥ ${fmtUs(S.slowThr)}（本会话 p90）` : '';

    const body = $('#sampleBody');
    if (!rows.length) {
      body.innerHTML = `<tr class="empty-row"><td colspan="11">${S.samples.length ? '没有符合筛选条件的样本' : '本会话没有样本（可能没有流量命中筛选条件）'}</td></tr>`;
      $('#tableMore').hidden = true;
      return;
    }
    const shown = rows.slice(0, S.shown);
    const maxS = S.maxSoj || 1;
    body.innerHTML = shown.map((s) => {
      const soj = s.max_sojourn_us;
      const w = isNum(soj) ? clamp(soj / maxS * 100, 1, 100) : 0;
      const heat = isNum(soj) && isSlow(s) ? (soj >= 10000 ? 'hot' : 'warm') : '';
      const nm = appName(s.uid);
      const who = s.comm || nm || '—';
      const whoTitle = [s.comm && 'comm ' + s.comm, nm && 'app ' + nm, s.tgid !== null && 'pid ' + s.tgid, s.enqueue_tid !== null && 'enqueue tid ' + s.enqueue_tid].filter(Boolean).join('\n');
      const status = completenessBadge(s) + (s.requeued ? ' <span class="badge badge-violet">Requeue</span>' : '');
      return `<tr data-id="${esc(s.sample_id)}" class="${S.activeSample !== null && s.sample_id === S.activeSample ? 'active' : ''}">
        <td class="num">${esc(s.sample_id === null ? '—' : s.sample_id)}</td>
        <td class="app-cell" title="${esc(whoTitle)}">${esc(who)}<span class="uid">${s.uid === null ? '' : 'uid ' + esc(s.uid)}</span></td>
        <td>${esc(String(s.proto || '—').toUpperCase())}</td>
        <td class="flow-cell" title="${esc((s.src || '?') + ' → ' + (s.dst || '?'))}">${esc(s.src || '?')} → ${esc(s.dst || '?')}</td>
        <td class="num">${esc(s.tcp_seq === null ? '—' : s.tcp_seq)}</td>
        <td class="num">${esc(s.pkt_len === null ? '—' : fmtInt(s.pkt_len))}</td>
        <td class="num"><div class="soj-cell"><span>${esc(fmtUs(soj))}</span><span class="soj-bar"><i class="${heat}" style="width:${w.toFixed(1)}%"></i></span></div></td>
        <td class="num">${esc(fmtUs(s.total_us))}</td>
        <td class="num">${esc(s.branch_count === null ? '—' : s.branch_count)}</td>
        <td>${endpointBadge(s.endpoint)}</td>
        <td>${status}</td>
      </tr>`;
    }).join('');
    $('#tableMore').hidden = rows.length <= S.shown;
    $('#btnMore').textContent = `显示更多（剩余 ${fmtInt(rows.length - S.shown)}）`;
  }
  function setPathFilter(prefix) {
    const same = prefix && S.filter.prefix && prefix.join('\u0001') === S.filter.prefix.join('\u0001');
    S.filter.prefix = same ? null : prefix;
    S.shown = 300;
    renderFlow();
    renderTable();
  }

  /* =====================================================================
   * 9. Single-packet drawer (waterfall + DAG + evidence)
   * ===================================================================== */
  function openDrawerShell() {
    $('#drawer').classList.add('open');
    $('#drawer').setAttribute('aria-hidden', 'false');
    $('#drawerMask').hidden = false;
    $('#drwSavedBar').hidden = !S.savedPath;
  }
  function closeDrawer() {
    $('#drawer').classList.remove('open');
    $('#drawer').setAttribute('aria-hidden', 'true');
    $('#drawerMask').hidden = true;
    S.activeSample = null;
    $$('#sampleBody tr.active').forEach((tr) => tr.classList.remove('active'));
  }
  async function openSample(id) {
    const sid = toNum(id);
    if (sid === null) return;
    S.activeSample = sid;
    $$('#sampleBody tr').forEach((tr) => tr.classList.toggle('active', toNum(tr.dataset.id) === sid));
    const row = S.samples.find((s) => s.sample_id === sid) || {};
    openDrawerShell();
    $('#drwTitle').textContent = `样本 #${sid} · 单包快递物流时间线`;
    $('#drwSub').innerHTML = subChips(row);
    $('#drwBody').innerHTML = '<div class="drawer-loading"><span class="spinner"></span> 正在重建单包路径…</div>';
    const token = ++S.detailToken;
    try {
      const d = await api('/api/session/sample?' + qs({ id: S.sessionId, sample_id: sid }), { timeout: 60000 });
      if (token !== S.detailToken) return;
      S.detail = obj(d);
      S.branchIdx = 0;
      const brs = arr(S.detail.branches);
      // default to the branch carrying the slowest queue visit
      let best = -1, bi = 0;
      brs.forEach((b, i) => { const m = Math.max(0, ...arr(obj(b).timeline).map((e) => toNum(obj(e).sojourn_us) || 0)); if (m > best) { best = m; bi = i; } });
      S.branchIdx = bi;
      renderDetail(row);
    } catch (e) {
      if (token !== S.detailToken) return;
      $('#drwBody').innerHTML = `<div class="banner banner-bad"><span class="ico">✖</span><div>加载样本失败：${esc(e.message)}</div></div>`;
    }
  }
  function subChips(row) {
    const c = [];
    if (row.comm || row.uid !== null && row.uid !== undefined) c.push(`<span class="chip chip-accent">${esc(row.comm || appName(row.uid) || '进程')}${row.uid !== null && row.uid !== undefined ? ' · uid ' + esc(row.uid) : ''}</span>`);
    if (row.proto) c.push(`<span class="chip">${esc(String(row.proto).toUpperCase())}</span>`);
    if (row.src || row.dst) c.push(`<span class="chip mono">${esc(row.src || '?')} → ${esc(row.dst || '?')}</span>`);
    if (row.tcp_seq !== null && row.tcp_seq !== undefined) c.push(`<span class="chip mono">seq ${esc(row.tcp_seq)}</span>`);
    if (row.pkt_len !== null && row.pkt_len !== undefined) c.push(`<span class="chip mono">${esc(row.pkt_len)} B</span>`);
    return c.join('');
  }
  function stageCat(ev) {
    const s = (String(ev.stage || '') + ' ' + String(ev.title || '')).toUpperCase();
    if (/DROP|丢/.test(s)) return 'drop';
    if (/ENTRY|入口/.test(s)) return 'entry';
    if (/XMIT|TX_OK|驱动/.test(s)) return 'xmit';
    if (/ENQ|DEQ|QDISC|CLASSIFY|REQUEUE|队/.test(s)) return 'queue';
    if (/CONSUME|DELIVER|释放/.test(s)) return 'end';
    if (/CLONE|COPY|SEGMENT|HANDOFF|MERGE/.test(s)) return 'transform';
    return 'other';
  }
  const CAT_COLOR = { entry: 'var(--accent)', queue: 'var(--warn)', xmit: 'var(--violet)', drop: 'var(--bad)', end: 'var(--ok)', transform: 'var(--info)', other: 'var(--text-3)' };
  function renderDetail(row) {
    const d = S.detail;
    const body = $('#drwBody');
    const brs = arr(d.branches).map(obj);
    let html = '';

    // ---- summary
    const sm = d.summary;
    const cells = [
      ['最大排队耗时', fmtUs(row.max_sojourn_us)], ['全程耗时', fmtUs(row.total_us)],
      ['支路数', row.branch_count === null || row.branch_count === undefined ? String(brs.length) : String(row.branch_count)],
      ['终点', row.endpoint || (brs[0] && brs[0].endpoint) || '—'],
    ];
    if (row.tgid !== null && row.tgid !== undefined) cells.push(['进程 pid', `${row.tgid}${row.comm ? ' / ' + row.comm : ''}`]);
    if (row.enqueue_tid !== null && row.enqueue_tid !== undefined) cells.push(['发包线程 tid', String(row.enqueue_tid)]);
    const skipSum = new Set(['sample_id', 'uid', 'tgid', 'comm', 'enqueue_tid', 'proto', 'src', 'dst', 'tcp_seq', 'pkt_len', 'max_sojourn_us', 'total_us', 'endpoint', 'branch_count', 'complete', 'completeness', 'requeued', 'path_sig', 'plugin_tags']);
    if (sm && typeof sm === 'object' && !Array.isArray(sm)) {
      if (sm.plugin_tags && typeof sm.plugin_tags === 'object' && !Array.isArray(sm.plugin_tags)) {
        for (const pk of Object.keys(sm.plugin_tags)) {
          if (cells.length >= 14) break;
          cells.push(['🔌 ' + pk, String(sm.plugin_tags[pk])]);
        }
      }
      for (const k of Object.keys(sm)) {
        if (skipSum.has(k)) continue;
        const v = sm[k];
        if (v === null || v === undefined || v === '' || typeof v === 'object') continue;
        if (cells.length >= 14) break;
        cells.push([k, String(v)]);
      }
    }
    html += `<div class="sum-grid">${cells.map(([k, v]) => `<div class="sum-cell"><div class="k">${esc(k)}</div><div class="v" title="${esc(v)}">${esc(v)}</div></div>`).join('')}</div>`;
    if (typeof sm === 'string' && sm.trim()) html += `<div class="banner banner-info"><span class="ico">ℹ</span><div>${esc(sm)}</div></div>`;

    if (!brs.length) {
      html += '<div class="banner banner-warn"><span class="ico">⚠</span><div>该样本没有可重建的支路（证据不足或数据块缺失）。</div></div>';
      body.innerHTML = html;
      return;
    }

    // ---- branch tabs + DAG
    if (brs.length > 1) {
      html += `<div class="section-title">支路（一个包被 clone / 分段后会分成多条支路）</div><div class="br-tabs">${brs.map((b, i) => `
        <button class="br-tab ${i === S.branchIdx ? 'active' : ''}" data-bi="${i}">
          ${b.complete ? '✔' : '⚠'} 支路 ${esc(b.branch_id === undefined ? i : b.branch_id)}${b.label ? ' · ' + esc(b.label) : ''} ${endpointBadge(b.endpoint)}
        </button>`).join('')}</div>`;
    }
    const rels = arr(d.relations).map(obj).filter((r) => r.src_object_id !== undefined && r.dst_object_id !== undefined);
    if (rels.length) html += renderDag(rels, brs[S.branchIdx]);

    const br = brs[S.branchIdx] || brs[0];
    const tl = arr(br.timeline).map(obj).slice().sort((a, b) => (toNum(a.rel_us) ?? 0) - (toNum(b.rel_us) ?? 0));
    const rels_ = tl.map((e) => toNum(e.rel_us)).filter((v) => v !== null);
    const t0 = rels_.length ? Math.min(0, ...rels_) : 0;
    const t1 = rels_.length ? Math.max(...rels_) : 0;

    if (!br.complete) {
      const reasons = arr(br.gap_reasons).filter(Boolean).map(esc).join('；');
      html += `<div class="banner banner-warn"><span class="ico">⚠</span><div><b>本支路${String(br.completeness || '').toLowerCase() === 'unknown' ? '完整性未知' : '不完整'}</b>${completenessText(br) ? `（完整度 ${esc(completenessText(br))}）` : ''}：${reasons || '部分跳转缺少直接证据，下方以 <b>红色虚线</b> 标出缺口。'}</div></div>`;
    }

    // ---- qstate backpressure
    for (const q of arr(d.qstates).map(obj)) {
      const s = toNum(q.start_rel_us), e = toNum(q.end_rel_us);
      if (s === null) continue;
      const ee = e === null ? Infinity : e;
      if (s > t1 || ee < t0) continue;
      const opNum = toNum(q.state_op);
      const op = String(q.state_name || (opNum !== null && QSTATE_NAMES[opNum]) || q.state_op || 'TXQ_STOP');
      const ov = Math.max(0, Math.min(ee, t1) - Math.max(s, t0));
      const isBql = /BQL/i.test(op);
      html += `<div class="banner banner-violet"><span class="ico">⛔</span><div>
        <b>${isBql ? 'BQL 字节限额生效' : '发送队列背压 (txq STOP → WAKE)'}</b> · txq ${esc(q.txq === undefined ? '?' : q.txq)} · ${esc(op)}${q.value !== undefined && q.value !== null && q.value !== '' ? ' = ' + esc(q.value) : ''}<br>
        从 <span class="num">+${esc(fmtUs(s))}</span> 到 <span class="num">${e === null ? '采集结束仍未恢复' : '+' + esc(fmtUs(e))}</span>，${isBql ? '驱动在途字节达到上限' : '驱动/固件缓冲已满，内核暂停从 qdisc 取包'}；与本包时间线重叠 <b class="num">${esc(e === null ? '≥ ' + fmtUs(ov) : fmtUs(ov))}</b>，这段排队并非 qdisc 本身慢。
      </div></div>`;
    }

    // ---- cross CPU / thread handoff summary
    const validCpu = (v) => { const c = toNum(v); return c !== null && c >= 0 && c < 1024 ? c : null; };
    const handoffs = [];
    let prevCpuEv = null;
    tl.forEach((ev, i) => {
      const cpu = validCpu(ev.cpu), tid = toNum(ev.tid);
      if (cpu === null && tid === null) return;
      if (prevCpuEv) {
        const pc = validCpu(prevCpuEv.cpu), pt = toNum(prevCpuEv.tid);
        const cpuDiff = cpu !== null && pc !== null && cpu !== pc;
        const tidDiff = tid !== null && pt !== null && tid !== pt;
        if (cpuDiff || tidDiff) handoffs.push({ i, from: prevCpuEv, to: ev, cpuDiff, tidDiff });
      }
      prevCpuEv = ev;
    });
    const handoffAt = new Map(handoffs.map((h) => [h.i, h]));
    const tidLbl = (t) => (toNum(t) === 0 ? 'tid 0 (softirq)' : 'tid ' + t);
    if (handoffs.length) {
      const h = handoffs.find((x) => stageCat(x.from) === 'queue' || stageCat(x.to) === 'xmit') || handoffs[0];
      const fc = validCpu(h.from.cpu), tc = validCpu(h.to.cpu);
      html += `<div class="banner banner-info"><span class="ico">⇄</span><div><b>检测到 ${handoffs.length} 次跨核/跨线程交接</b>：
        「${esc(h.from.title || h.from.stage || '前一步')}」在 <b>${fc !== null ? 'CPU ' + esc(fc) + ' · ' : ''}${esc(tidLbl(h.from.tid ?? '?'))}</b>，
        「${esc(h.to.title || h.to.stage || '后一步')}」在 <b>${tc !== null ? 'CPU ' + esc(tc) + ' · ' : ''}${esc(tidLbl(h.to.tid ?? '?'))}</b>。
        包入队后由另一个核/线程（常见为 softirq / qdisc_run 所有者）负责出队发送。</div></div>`;
    }

    // ---- waterfall
    html += renderWaterfall(tl, t0, t1);

    // ---- object chain
    const chain = arr(br.object_chain);
    if (chain.length) {
      html += `<div class="section-title">对象链 (skb object_id)</div><div class="obj-chain">${chain.map((o) => `<span class="chip mono">${esc(typeof o === 'object' ? (o.object_id ?? JSON.stringify(o)) : o)}</span>`).join('<span class="arrow">→</span>')}</div>`;
    }

    // ---- step cards
    html += `<div class="ev-tools">
        <div class="section-title" style="margin:0">逐跳证据（${tl.length} 步）</div>
        <label class="check"><input type="checkbox" id="chkRaw" ${S.showRaw ? 'checked' : ''}><span>显示原始探针证据</span></label>
        <div class="ev-legend">${[1, 2, 3, 4].map((l) => `<span class="badge lv-badge lv-${l}"${tipAttr(esc(LV_TIP[l]))}>${LV_LABEL[l]}</span>`).join('')}</div>
      </div>`;
    let prevRel = null;
    const thr = Math.max(S.slowThr || 0, 1000);
    const cards = tl.map((ev, i) => {
      const lv = evLevel(ev);
      const rel = toNum(ev.rel_us);
      const dlt = prevRel !== null && rel !== null ? rel - prevRel : null;
      if (rel !== null) prevRel = rel;
      const soj = toNum(ev.sojourn_us);
      const slow = soj !== null && soj >= thr;
      const ec = validCpu(ev.cpu);
      let pre = '';
      const h = handoffAt.get(i);
      if (h) {
        const parts = [];
        if (h.cpuDiff) parts.push(`跨核 CPU ${esc(validCpu(h.from.cpu))} → CPU ${esc(validCpu(h.to.cpu))}`);
        if (h.tidDiff) parts.push(`跨线程 ${esc(tidLbl(h.from.tid))} → ${esc(tidLbl(h.to.tid))}`);
        pre = `<div class="ev-handoff"><div class="banner banner-info"><span class="ico">⇄</span><div><b>交接</b> · ${parts.join(' · ')}</div></div></div>`;
      }
      const raw = [
        ev.ts_ns !== undefined && ev.ts_ns !== null ? `ts_ns=${esc(ev.ts_ns)}` : '',
        ev.event_id !== undefined && ev.event_id !== null ? `event_id=${esc(ev.event_id)}` : '',
        ev.probe_name ? `probe=${esc(ev.probe_name)}${ev.probe_version ? '@' + esc(ev.probe_version) : ''}` : '',
        ev.adapter_name ? `adapter=${esc(ev.adapter_name)}` : '',
        ev.stage !== undefined && ev.stage !== null ? `stage=${esc(ev.stage)}` : '',
      ].filter(Boolean).map((x) => `<span>${x}</span>`).join('');
      return `${pre}<div class="ev-card">
        <div class="ev-time"><div class="abs">${rel === null ? '—' : '+' + esc(fmtUs(rel))}</div>${dlt !== null && i > 0 ? `<div class="dlt">Δ ${esc(fmtUs(dlt))}</div>` : ''}</div>
        <div class="ev-box lv${lv} ${slow ? 'slow' : ''}">
          <div class="ev-top">
            <span class="badge lv-badge lv-${lv}"${tipAttr(esc(LV_TIP[lv]))}>${esc(ev.evidence_label || LV_LABEL[lv])}</span>
            <span class="ev-title">${esc(ev.title || ev.stage || '事件')}</span>
            ${soj !== null && soj > 0 ? `<span class="badge ${slow ? 'badge-bad' : 'badge-warn'} ev-soj">排队 ${esc(fmtUs(soj))}</span>` : ''}
            <span class="spacer"></span>
            ${ec !== null ? `<span class="badge badge-muted cpu-badge">CPU ${esc(ec)}</span>` : ''}
            ${toNum(ev.tid) !== null ? `<span class="badge badge-muted cpu-badge">${esc(tidLbl(ev.tid))}</span>` : ''}
          </div>
          ${ev.detail ? `<div class="ev-detail">${esc(ev.detail)}</div>` : ''}
          ${lv === 4 && !ev.detail ? `<div class="ev-detail">${esc(LV_TIP[4])}</div>` : ''}
          ${raw ? `<div class="ev-raw">${raw}</div>` : ''}
        </div></div>`;
    }).join('');
    html += `<div class="ev-list ${S.showRaw ? '' : 'hide-raw'}" id="evList">${cards || '<div class="empty-mini">该支路没有事件</div>'}</div>`;
    body.innerHTML = html;
  }
  function renderWaterfall(tl, t0, t1) {
    const span = Math.max(t1 - t0, 0.001);
    const pos = (v) => clamp(((toNum(v) ?? t0) - t0) / span * 100, 0, 100);
    // overview segments between consecutive events
    let segs = '';
    for (let i = 1; i < tl.length; i++) {
      const a = toNum(tl[i - 1].rel_us), b = toNum(tl[i].rel_us);
      if (a === null || b === null) continue;
      const w = (b - a) / span * 100;
      if (w <= 0) continue;
      const ev = tl[i];
      const cat = toNum(ev.sojourn_us) > 0 ? 'queue' : stageCat(ev);
      const lv = evLevel(ev);
      const lbl = ev.title || ev.stage || '';
      const tip = `<div class="tt-title">${esc(tl[i - 1].title || tl[i - 1].stage || '')} → ${esc(lbl)}</div>耗时 ${esc(fmtUs(b - a))}（占全程 ${esc(fmtPct((b - a) / span))}）`;
      const style = lv === 4
        ? `width:${w.toFixed(3)}%;background:repeating-linear-gradient(45deg,var(--bad) 0 4px,transparent 4px 8px);`
        : `width:${w.toFixed(3)}%;background:${CAT_COLOR[cat]};`;
      segs += `<div class="wf-seg" style="${style}"${tipAttr(tip)}>${w > 9 ? `<span>${esc(fmtUs(b - a))}</span>` : ''}</div>`;
    }
    if (!segs) segs = '<div class="wf-seg" style="width:100%;background:var(--border)"></div>';
    // gantt rows
    const rows = tl.slice(0, 80).map((ev) => {
      const rel = toNum(ev.rel_us);
      const soj = toNum(ev.sojourn_us);
      const cat = soj > 0 ? 'queue' : stageCat(ev);
      const lv = evLevel(ev);
      const color = lv === 4 ? 'var(--bad)' : CAT_COLOR[cat];
      let mark;
      if (soj !== null && soj > 0 && rel !== null) {
        const l = pos(rel - soj), r = pos(rel);
        mark = `<div class="bar" style="left:${l.toFixed(2)}%;width:${Math.max(r - l, 0.4).toFixed(2)}%;background:${color};${lv === 4 ? 'opacity:.55;' : ''}"></div>`;
      } else {
        mark = `<div class="tick" style="left:calc(${pos(rel).toFixed(2)}% - 1px);background:${color}"></div>`;
      }
      const tip = `<div class="tt-title">${esc(ev.title || ev.stage || '')}</div>+${esc(fmtUs(rel))}${soj ? `<br>排队驻留 ${esc(fmtUs(soj))}` : ''}${ev.detail ? '<br>' + esc(ev.detail) : ''}`;
      return `<div class="wf-row"${tipAttr(tip)}><div class="lbl">${esc(ev.title || ev.stage || '事件')}</div><div class="trk">${mark}</div><div class="val">${soj ? esc(fmtUs(soj)) : '+' + esc(fmtUs(rel))}</div></div>`;
    }).join('');
    return `<div class="wf">
      <div class="wf-head"><h4>时间比例瀑布图</h4><span class="hint">横向长度 = 真实耗时 · 橙色条 = 在队列里排队</span><span class="spacer"></span><span class="badge badge-muted num">全程 ${esc(fmtUs(t1 - t0))}</span></div>
      <div class="wf-overview">${segs}</div>
      <div class="wf-axis"><span>+0</span><span>${esc(fmtUs(t0 + span / 4))}</span><span>${esc(fmtUs(t0 + span / 2))}</span><span>${esc(fmtUs(t0 + span * 3 / 4))}</span><span>${esc(fmtUs(t1))}</span></div>
      <div class="wf-rows">${rows}</div>
    </div>`;
  }
  function renderDag(rels, br) {
    const ids = [];
    const idx = new Map();
    const add = (id) => { const k = String(id); if (!idx.has(k)) { idx.set(k, ids.length); ids.push(k); } };
    rels.forEach((r) => { add(r.src_object_id); add(r.dst_object_id); });
    if (ids.length > 40) return '';
    // levels via longest path from roots
    const level = new Map(ids.map((k) => [k, 0]));
    for (let it = 0; it < ids.length; it++) {
      let changed = false;
      for (const r of rels) {
        const a = String(r.src_object_id), b = String(r.dst_object_id);
        if (a === b) continue;
        if (level.get(b) < level.get(a) + 1 && level.get(a) + 1 < ids.length) { level.set(b, level.get(a) + 1); changed = true; }
      }
      if (!changed) break;
    }
    const byLv = new Map();
    ids.forEach((k) => { const l = level.get(k); (byLv.get(l) || byLv.set(l, []).get(l)).push(k); });
    const NW = 116, NH = 26, CX = 170, CY = 38;
    const pos = new Map();
    let maxRows = 1;
    byLv.forEach((list, l) => { maxRows = Math.max(maxRows, list.length); list.forEach((k, i) => pos.set(k, { x: 10 + l * CX, y: 10 + i * CY })); });
    const W = 20 + (Math.max(...byLv.keys()) + 1) * CX - (CX - NW);
    const H = 20 + maxRows * CY - (CY - NH) + 4;
    const mine = new Set(arr(br && br.object_chain).map((o) => String(typeof o === 'object' && o ? o.object_id : o)));
    let svg = `<defs><marker id="dagArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--text-3)"/></marker></defs>`;
    for (const r of rels) {
      const a = pos.get(String(r.src_object_id)), b = pos.get(String(r.dst_object_id));
      if (!a || !b) continue;
      const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
      const mx = (x1 + x2) / 2;
      const rl = (toNum(r.rel_type) !== null && REL_NAMES[toNum(r.rel_type)]) || r.rel_type_name || r.rel_type || '';
      svg += `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 2},${y2}" fill="none" stroke="var(--text-3)" stroke-width="1.4" marker-end="url(#dagArrow)"/>`;
      svg += `<text x="${mx}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--info)">${esc(rl)}</text>`;
    }
    pos.forEach((p, k) => {
      const hl = mine.has(k);
      const lbl = k.length > 16 ? '…' + k.slice(-15) : k;
      svg += `<g><rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="6" fill="${hl ? 'var(--accent-soft)' : 'var(--surface-2)'}" stroke="${hl ? 'var(--accent)' : 'var(--border-strong)'}" stroke-width="${hl ? 1.8 : 1}"/><text x="${p.x + NW / 2}" y="${p.y + 17}" text-anchor="middle" font-size="10.5" fill="var(--text)"><title>${esc(k)}</title>obj ${esc(lbl)}</text></g>`;
    });
    return `<div class="section-title">对象关系 DAG（蓝框 = 当前支路经过的对象）</div><div class="dag"><svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">${svg}</svg></div>`;
  }

  /* =====================================================================
   * 10. Export, Explorer Reveal & App Lifecycle
   * ===================================================================== */
  function showSavedBar(fullPath, labelText) {
    const p = String(fullPath || '').trim();
    if (!p) return;
    S.savedPath = p;
    const lbl = labelText || '已保存：';
    $('#savedLabel').textContent = lbl;
    $('#savedPath').textContent = p;
    $('#savedPath').title = p;
    $('#savedBar').hidden = false;
    $('#drwSavedLabel').textContent = lbl;
    $('#drwSavedPath').textContent = p;
    $('#drwSavedPath').title = p;
    $('#drwSavedBar').hidden = !$('#drawer').classList.contains('open');
  }
  function hideSavedBar() {
    S.savedPath = '';
    $('#savedBar').hidden = true;
    $('#drwSavedBar').hidden = true;
  }
  async function revealPath(targetPath) {
    const p = String(targetPath || '').trim();
    if (!p) {
      toast('当前没有可打开的本地路径', 'warn');
      return;
    }
    try {
      const r = await api('/api/dialog/reveal', { body: { path: p }, timeout: 15000 });
      toast('已在资源管理器中打开：' + (r.path || p), 'ok');
    } catch (e) {
      toast('打开所在文件夹失败：' + e.message, 'bad');
    }
  }
  async function copyPath(text) {
    const s = String(text || '').trim();
    if (!s) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(s);
      } else {
        const ta = document.createElement('textarea');
        ta.value = s;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      toast('已复制路径：' + s, 'ok');
    } catch (e) {
      toast('复制路径失败：' + e.message, 'bad');
    }
  }
  async function exportPcap(redact) {
    if (!S.sessionId) return;
    const defaultName = 'trace_' + S.sessionId + (redact ? '_redacted' : '') + '.pcapng';
    if (DEMO) {
      const blob = new Blob([new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a])], { type: 'application/x-pcapng' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = defaultName;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 5000);
      const demoPath = 'C:\\Users\\demo\\Downloads\\' + defaultName;
      showSavedBar(demoPath, '已保存：');
      toast('演示模式：已生成示例路径 ' + demoPath, 'ok');
      return;
    }
    try {
      const r = await api('/api/dialog/save-file', {
        body: {
          default_name: defaultName,
          filter: 'Wireshark Capture (*.pcapng)|*.pcapng|All Files (*.*)|*.*',
        },
        timeout: 0,
      });
      if (!r || r.cancelled || !r.path) return;
      toast(redact ? '正在导出脱敏 pcapng…' : '正在导出 tcpdump / Wireshark (.pcapng)…');
      const out = await api('/api/session/export-pcapng', {
        body: { id: S.sessionId, out_path: r.path, redact: !!redact },
        timeout: 180000,
      });
      const saved = out.out_path || r.path;
      showSavedBar(saved, '已保存：');
      const pktNote = out.exported_packets !== undefined ? `（共 ${fmtInt(out.exported_packets)} 个包）` : '';
      toast(`已保存${pktNote}：${saved}`, 'ok', 5500);
    } catch (e) {
      if (!/cancel/i.test(e.message)) toast('导出 pcapng 失败：' + e.message, 'bad');
    }
  }
  async function exportRedacted() {
    if (!S.sessionId) return;
    try {
      toast('请选择脱敏包的保存目录…');
      const r = await api('/api/dialog/pick-folder', { body: {}, timeout: 0 });
      if (!r || r.cancelled || !r.path) return;
      const sess = S.sessions.find((x) => x.id === S.sessionId) || {};
      const base = (sess.name || baseName(sess.path) || S.sessionId || 'session').replace(/[^A-Za-z0-9._-]+/g, '-');
      let outDir = String(r.path).replace(/[\\/]+$/, '');
      if (!/_redacted$/i.test(baseName(outDir))) {
        const sep = outDir.includes('/') && !outDir.includes('\\') ? '/' : '\\';
        outDir = outDir + sep + base + '_redacted';
      }
      const o = await api('/api/session/redact', { body: { id: S.sessionId, out_dir: outDir }, timeout: 180000 });
      const saved = o.out_dir || o.path || outDir;
      showSavedBar(saved, '已保存：');
      toast(`脱敏包已保存：${saved}（IP / 端口 / UID 已匿名化）`, 'ok', 6000);
      loadSessions();
    } catch (e) {
      if (!/cancel/i.test(e.message)) toast('导出脱敏包失败：' + e.message, 'bad');
    }
  }
  function connectAppEvents() {
    if (DEMO || typeof EventSource === 'undefined') return;
    try {
      S.es = new EventSource('/api/app/events');
    } catch (_) {
      S.es = null;
    }
    window.addEventListener('pagehide', () => {
      if (S.es) { try { S.es.close(); } catch (_) { /* ignore */ } S.es = null; }
    });
  }
  async function quitApp() {
    if (S.quitting) return;
    if (S.capturing && !window.confirm('当前正在采集中，退出服务将自动停止采集并安全清理手机端临时文件，确定退出吗？')) {
      return;
    }
    S.quitting = true;
    $('#btnQuitApp').disabled = true;
    clearInterval(S.pollTimer);
    clearInterval(S.tickTimer);
    clearInterval(S.devTimer);
    if (S.es) { try { S.es.close(); } catch (_) { /* ignore */ } S.es = null; }
    try {
      await api('/api/app/quit', { body: {}, timeout: 15000 });
    } catch (_) { /* server may exit immediately upon flushing response */ }
    $('#quitModal').hidden = false;
  }

  /* =====================================================================
   * 11. UI bindings
   * ===================================================================== */
  function setSeg(el, v) { $$('button', el).forEach((b) => b.classList.toggle('active', b.dataset.v === v)); }
  function bindSeg(el, cb) {
    el.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-v]');
      if (!b || b.disabled) return;
      setSeg(el, b.dataset.v);
      cb(b.dataset.v);
    });
  }
  function bindUI() {
    $('#btnTheme').addEventListener('click', toggleTheme);
    $('#btnQuitApp').addEventListener('click', quitApp);
    $('#btnRailToggle').addEventListener('click', toggleRail);
    $('#btnRefreshDevices').addEventListener('click', () => refreshDevices(true));
    $('#devicePill').addEventListener('click', () => { if (document.body.classList.contains('rail-collapsed')) toggleRail(); (S.transport === 'ssh' ? $('#selSSH') : $('#selDevice')).focus(); });
    $('#btnOpenPlugins').addEventListener('click', openPluginDrawer);
    $('#btnManagePluginsInline').addEventListener('click', openPluginDrawer);
    $('#plugClose').addEventListener('click', closePluginDrawer);
    $('#pluginMask').addEventListener('click', closePluginDrawer);
    $('#btnImportPlugin').addEventListener('click', startImportPlugin);
    $('#btnRefreshPlugins').addEventListener('click', () => { loadPlugins(); toast('已刷新插件列表', 'ok'); });
    $('#plugPreview').addEventListener('click', (e) => {
      if (e.target.closest('#btnConfirmImportPlugin')) confirmImportPlugin();
      else if (e.target.closest('#btnCancelImportPlugin')) { S.pendingPlugin = null; renderPluginPreview(); }
    });
    $('#plugList').addEventListener('change', (e) => {
      const inp = e.target.closest('.plug-toggle');
      if (inp) togglePlugin(inp.dataset.file, inp.checked);
    });
    $('#plugList').addEventListener('click', (e) => {
      const del = e.target.closest('.plug-del');
      if (del) deletePlugin(del.dataset.file);
    });
    $('#btnOpenFolder').addEventListener('click', openFolder);
    $('#btnHistory').addEventListener('click', (e) => { e.stopPropagation(); toggleHistory(); });
    $('#btnHistoryReload').addEventListener('click', (e) => { e.stopPropagation(); loadSessions(); });
    $('#historyList').addEventListener('click', (e) => {
      const b = e.target.closest('.hist-item');
      if (!b) return;
      const s = S.sessions[Number(b.dataset.i)];
      toggleHistory(false);
      if (s) showSession(s.id);
    });
    document.addEventListener('click', (e) => {
      if (!e.target.closest('#historyDropdown')) toggleHistory(false);
      if (!e.target.closest('#appCombo')) $('#appList').hidden = true;
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if ($('#pluginDrawer').classList.contains('open')) closePluginDrawer();
        else if (!$('#historyMenu').hidden) toggleHistory(false);
        else if ($('#drawer').classList.contains('open')) closeDrawer();
      }
    });

    // ① target device (ADB / SSH) & iface
    bindSeg($('#segTransport'), (v) => switchTransport(v));
    $('#selDevice').addEventListener('change', (e) => selectDevice(e.target.value));
    $('#selSSH').addEventListener('change', (e) => selectDevice(e.target.value));
    $('#btnToggleSSHForm').addEventListener('click', () => {
      const f = $('#sshForm');
      f.hidden = !f.hidden;
      $('#sshTestOut').hidden = true;
      if (!f.hidden) $('#sshHost').focus();
    });
    $('#btnSSHCancel').addEventListener('click', () => { $('#sshForm').hidden = true; $('#sshTestOut').hidden = true; });
    $('#btnSSHTest').addEventListener('click', testSSHConnection);
    $('#btnSSHSave').addEventListener('click', saveSSHHost);
    $('#btnDeleteSSH').addEventListener('click', deleteCurrentSSH);
    $('#btnPickSSHKey').addEventListener('click', pickSSHKeyFile);
    $('#selIface').addEventListener('change', (e) => {
      S.iface = e.target.value;
      updateStartBtn();
      if (S.serial && S.iface) loadInspect(S.serial, S.iface);
    });
    $('#selScope').addEventListener('change', () => { if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface); });
    $('#chkPlugins').addEventListener('change', () => { if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface); });
    $('#btnRevealPlugins').addEventListener('click', () => {
      if (S.pluginsDir) revealPath(S.pluginsDir);
      else toast('尚未获取插件目录路径', 'warn');
    });

    // ② apps
    const inp = $('#appSearch');
    inp.addEventListener('focus', renderCombo);
    inp.addEventListener('input', renderCombo);
    inp.addEventListener('keydown', (e) => {
      if ($('#appList').hidden && (e.key === 'ArrowDown' || e.key === 'Enter')) { renderCombo(); e.preventDefault(); return; }
      if (e.key === 'ArrowDown') { comboMove(1); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { comboMove(-1); e.preventDefault(); }
      else if (e.key === 'Enter') { chooseApp(comboItems[comboHl]); e.preventDefault(); }
      else if (e.key === 'Escape') { $('#appList').hidden = true; e.stopPropagation(); }
    });
    $('#appList').addEventListener('mousedown', (e) => {
      const b = e.target.closest('.combo-item');
      if (!b) return;
      e.preventDefault();
      chooseApp(comboItems[Number(b.dataset.i)]);
      inp.blur();
    });
    $('#appChosenText').addEventListener('click', () => inp.focus());
    bindSeg($('#segProto'), (v) => { S.proto = v; });

    // ③ mode
    $('#modeTabs').addEventListener('click', (e) => {
      const t = e.target.closest('.tab');
      if (!t || S.capturing) return;
      S.mode = t.dataset.mode;
      $$('#modeTabs .tab').forEach((x) => x.classList.toggle('active', x === t));
      $$('.tab-pane').forEach((p) => { p.hidden = p.dataset.pane !== S.mode; });
      updateStartBtn();
    });
    bindSeg($('#segSample'), (v) => { S.sample = v; });
    bindSeg($('#segDuration'), (v) => { S.duration = Number(v) || 10; updateStartBtn(); });
    bindSeg($('#segDSample'), (v) => { S.dsample = v; });
    $('#inpThreshold').addEventListener('input', (e) => { $('#thrLabel').textContent = e.target.value; });
    $('#btnStart').addEventListener('click', startCapture);
    $('#btnStop').addEventListener('click', () => stopCapture(false));
    $('#btnFlush').addEventListener('click', flushCapture);

    // canvas & saved-path bar
    $('#btnRevealSession').addEventListener('click', () => revealPath(currentSessionPath() || (DEMO ? 'C:\\Users\\demo\\AppData\\Local\\PktPathStudio\\sessions\\' + S.sessionId : '')));
    $('#btnExportPcap').addEventListener('click', (e) => exportPcap(e.shiftKey));
    $('#btnExportRedact').addEventListener('click', exportRedacted);
    $('#drwExportPcap').addEventListener('click', (e) => exportPcap(e.shiftKey));
    $('#drwExportRedact').addEventListener('click', exportRedacted);
    $('#btnExportPcap').title += '（按住 Shift 点击 = 导出脱敏 pcapng）';
    $('#btnSavedReveal').addEventListener('click', () => revealPath(S.savedPath));
    $('#btnSavedCopy').addEventListener('click', () => copyPath(S.savedPath));
    $('#btnSavedClose').addEventListener('click', hideSavedBar);
    $('#btnDrwSavedReveal').addEventListener('click', () => revealPath(S.savedPath));
    $('#btnDrwSavedCopy').addEventListener('click', () => copyPath(S.savedPath));
    $('#btnDrwSavedClose').addEventListener('click', hideSavedBar);
    $('#flowWrap').addEventListener('click', (e) => {
      const g = e.target.closest('[data-prefix]');
      if (!g) return;
      try { setPathFilter(JSON.parse(g.getAttribute('data-prefix'))); } catch (_) { /* ignore */ }
    });
    $('#btnClearPath').addEventListener('click', () => setPathFilter(null));
    $('#pathChip').addEventListener('click', () => setPathFilter(null));
    $('#tblSearch').addEventListener('input', debounce((e) => { S.filter.q = e.target.value; S.shown = 300; renderTable(); }, 150));
    $('#tblSeq').addEventListener('input', debounce((e) => { S.filter.seq = e.target.value; S.shown = 300; renderTable(); }, 150));
    $('#tblUid').addEventListener('change', (e) => { S.filter.uid = e.target.value; S.shown = 300; renderTable(); });
    bindSeg($('#segStatus'), (v) => { S.filter.status = v; S.shown = 300; renderTable(); });
    $('#sampleTable thead').addEventListener('click', (e) => {
      const th = e.target.closest('th[data-k]');
      if (!th) return;
      const k = th.dataset.k;
      const numeric = ['sample_id', 'tcp_seq', 'pkt_len', 'max_sojourn_us', 'total_us', 'branch_count'].includes(k);
      S.sort = S.sort.k === k ? { k, dir: -S.sort.dir } : { k, dir: numeric ? -1 : 1 };
      renderTable();
    });
    $('#sampleBody').addEventListener('click', (e) => {
      const tr = e.target.closest('tr[data-id]');
      if (tr) openSample(tr.dataset.id);
    });
    $('#btnMore').addEventListener('click', () => { S.shown += 500; renderTable(); });

    // drawer
    $('#drwClose').addEventListener('click', closeDrawer);
    $('#drawerMask').addEventListener('click', closeDrawer);
    $('#drwBody').addEventListener('click', (e) => {
      const b = e.target.closest('.br-tab');
      if (b) {
        S.branchIdx = Number(b.dataset.bi) || 0;
        const row = S.samples.find((s) => s.sample_id === S.activeSample) || {};
        renderDetail(row);
      }
    });
    $('#drwBody').addEventListener('change', (e) => {
      if (e.target && e.target.id === 'chkRaw') {
        S.showRaw = e.target.checked;
        const l = $('#evList');
        if (l) l.classList.toggle('hide-raw', !S.showRaw);
      }
    });

    window.addEventListener('resize', debounce(renderCharts, 150));
    document.addEventListener('visibilitychange', () => { if (!document.hidden && !S.capturing && !S.quitting) refreshDevices(false); });
  }

  /* =====================================================================
   * 12. Demo backend (offline preview: ?demo=1 or file://)
   * ===================================================================== */
  const Demo = (function () {
    let seed = 20261124;
    const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
    const DEMO_CLASSES = [
      { kind: 'htb', handle: 0x10001, parent: 0xffffffff, leaf: 0, prio: 0, rate_bps: 1000000000, ceil_bps: 1000000000, bytes: 98420100, packets: 84210, drops: 0, overlimits: 0 },
      { kind: 'htb', handle: 0x10010, parent: 0x10001, leaf: 0, prio: 1, rate_bps: 10000000, ceil_bps: 20000000, bytes: 421800, packets: 412, drops: 0, overlimits: 19 },
      { kind: 'htb', handle: 0x10020, parent: 0x10001, leaf: 0x120000, prio: 2, rate_bps: 100000000, ceil_bps: 200000000, bytes: 97998300, packets: 83798, drops: 0, overlimits: 4 },
      { kind: 'htb', handle: 0x10030, parent: 0x10001, leaf: 0x140000, prio: 3, rate_bps: 5000000, ceil_bps: 5000000, bytes: 2840100, packets: 3571, drops: 0, overlimits: 128 },
    ];
    const PATHS = [
      { sig: 'ENTRY(wlan0) -> HTB:1: -> CLASS:1:20 -> FQ_CODEL:12: -> XMIT(wlan0:txq11) -> TX_OK', w: 32 },
      { sig: 'ENTRY(wlan0) -> HTB:1: -> CLASS:1:10 -> PFIFO@1:10 -> XMIT(wlan0:txq11) -> TX_OK', w: 12 },
      { sig: 'ENTRY(wlan0) -> HTB:1: -> CLASS:1:30 -> SFQ:14: -> XMIT(wlan0:txq2) -> TX_OK', w: 8 },
      { sig: 'ENTRY(wlan0) -> CONSUME', w: 4 },
    ];
    let capStart = 0, capMode = 'oneshot', sessions = [], overviews = {};
    const comms = [['ping', 0], ['com.android.chrome', 10150], ['com.tencent.mm', 10234], ['iperf3', 2000]];
    function makeOverview() {
      seed = 7;
      const samples = [];
      for (let i = 0; i < 64; i++) {
        let r = rnd() * 56, p = PATHS[0];
        for (const x of PATHS) { if (r < x.w) { p = x; break; } r -= x.w; }
        const [comm, uid] = comms[Math.floor(rnd() * comms.length)];
        const isTcp = uid !== 0;
        const slow = rnd() < 0.08 || p.sig.includes('SFQ:14:');
        const soj = p.sig.endsWith('CONSUME') ? 0 : (slow ? 8000 + rnd() * 24000 : 20 + rnd() * rnd() * 400);
        const complete = !(p.sig.endsWith('DROP')) && rnd() > 0.04;
        samples.push({
          sample_id: i + 1, uid, tgid: 2190 + uid % 97, comm: comm.split('.').pop(), enqueue_tid: 2190 + uid % 97 + (i % 4),
          proto: isTcp ? 'tcp' : 'icmp', src: isTcp ? `192.0.2.57:${40000 + (i % 7)}` : '192.0.2.57', dst: isTcp ? '198.51.100.10:443' : '192.0.2.1',
          tcp_seq: isTcp ? 90001 + i * 1000 : null, pkt_len: isTcp ? 1500 - Math.floor(rnd() * 1300) : 98,
          max_sojourn_us: soj, total_us: soj + 30 + rnd() * 120, complete, completeness: complete ? 'complete' : 'incomplete',
          endpoint: p.sig.split(' -> ').pop(), branch_count: p.sig.endsWith('CONSUME') ? 1 : (i % 5 === 0 ? 2 : 1),
          requeued: p.sig.includes('REQUEUE'), path_sig: p.sig,
        });
      }
      const paths = PATHS.map((p) => {
        const ss = samples.filter((s) => s.path_sig === p.sig);
        const t = ss.map((s) => s.total_us).sort((a, b) => a - b);
        return { path_sig: p.sig, count: ss.length, complete_count: ss.filter((s) => s.complete).length, p50_us: percentile(t, 0.5), p95_us: percentile(t, 0.95), p99_us: percentile(t, 0.99), wire_bytes: 0, skb_bytes: 0 };
      }).filter((p) => p.count);
      const qstat = (label, kind, handle, parent, gen, classRate, classPrio, sub) => {
        const v = samples.filter((s) => sub(s) && s.max_sojourn_us > 0).map((s) => s.max_sojourn_us).sort((a, b) => a - b);
        return { label, kind, handle, parent, queue_gen: gen, class_rate: classRate, class_prio: classPrio, paired_n: v.length, p50_us: percentile(v, 0.5), p95_us: percentile(v, 0.95), p99_us: percentile(v, 0.99), max_us: v[v.length - 1], drop_count: 0 };
      };
      const queues = [
        qstat('wlan0 SFQ 14: (gen=44)', 'sfq', '14:', '1:30', 44, '5M', 3, (s) => s.path_sig.includes('SFQ:14:')),
        qstat('wlan0 FQ_CODEL 12: (gen=43)', 'fq_codel', '12:', '1:20', 43, '100M→200M', 2, (s) => s.path_sig.includes('FQ_CODEL:12:')),
        qstat('wlan0 PFIFO @ 1:10', 'pfifo', '0:', '1:10', 47, '10M→20M', 1, (s) => s.path_sig.includes('PFIFO@1:10')),
      ];
      const nb = samples.reduce((a, s) => a + s.branch_count, 0);
      const comp = samples.filter((s) => s.complete).reduce((a, s) => a + s.branch_count, 0);
      return {
        manifest: { dev: 'wlan0', scope: 'tc-egress', mode: 'oneshot', kernel_release: '6.1.157-android14-11', sample_rate: '1/1', sample_by: 'pkt', calibrations: [{ realtime_ns: Date.now() * 1e6 }], partial_coverage: false },
        dict: { topology_epochs: [{ epoch_id: 1, classes: DEMO_CLASSES }] },
        stats: {
          admissions: { filter_unknown: 0, matched: 71, selected: 64, created: 64, rejected: 0 },
          branches: { total: nb, complete: comp, incomplete: nb - comp, unknown: 0 },
          paths, queues, endpoints: {}, requeue_count: samples.filter((s) => s.requeued).length, reorder_count: 1,
          skb_bytes: 0, wire_bytes: 0, unclean_tail: false, quality_alerts: [],
        },
        samples,
      };
    }
    function makeSample(ov, sid) {
      const s = ov.samples.find((x) => x.sample_id === sid) || ov.samples[0];
      const toks = s.path_sig.split(' -> ');
      const mk = (complete, ep, cloneOnly) => {
        const tl = [];
        let t = 0;
        const ev = (title, stage, detail, extra) => { tl.push(Object.assign({ rel_us: +t.toFixed(2), ts_ns: 1628227047164000 + Math.round(t * 1000), evidence_level: 1, evidence_label: '直接观测', stage, title, detail, sojourn_us: 0, cpu: 3, tid: s.enqueue_tid, event_id: 1000 + tl.length, probe_name: 'tp_' + stage.toLowerCase(), probe_version: '1.0', adapter_name: 'l2_tc_egress_core' }, extra || {})); };
        ev('进入网卡出口 (dev_queue_xmit)', 'ENTRY', `${s.src} → ${s.dst} len=${s.pkt_len}`);
        if (cloneOnly) { t += 6; ev('克隆副本被释放 (consume_skb)', 'CONSUME', 'tcp 重传副本'); return tl; }
        for (const tok of toks.slice(1, -1)) {
          t += 1.5 + rnd() * 3;
          if (/^CLASS:/.test(tok)) ev(`TC 规则命中子类 CLASS ${tok.slice(6)}`, 'CLASSIFY', 'tcf_classify 返回目标 classid', { probe_name: 'kr_tcf_classify', adapter_name: 'l2_tc_classify' });
          else if (/^HTB:/.test(tok)) ev(`进入分层队列 ${tok.replace(':', ' ')}`, 'CLASSIFY', 'classful qdisc 分类调度', { probe_name: 'kp_htb_enqueue' });
          else if (/^(FQ_CODEL|SFQ):/.test(tok) || /@/.test(tok)) {
            const ql = tok.includes('@') ? tok.replace('@', ' @ ') : tok.replace(':', ' ');
            ev(`进入叶子队列 ${ql}`, 'QDISC_ENQ', 'enqueue ret=NET_XMIT_SUCCESS');
            t += s.max_sojourn_us;
            ev(`离开叶子队列 ${ql}`, 'QDISC_DEQ', 'qdisc 出队', { sojourn_us: s.max_sojourn_us, cpu: 2, tid: 0 });
          } else if (tok === 'REQUEUE_GSO') ev('GSO 拆分后重新排队', 'REQUEUE_GSO', 'dev_requeue_skb 未覆盖，按契约推导', { evidence_level: complete ? 2 : 4, evidence_label: complete ? '契约推导' : '缺口/未知', cpu: 2, tid: 0 });
          else if (/^XMIT/.test(tok)) { ev('交给驱动 ndo_start_xmit', 'XMIT_START', tok.replace(/^XMIT\(|\)$/g, ''), { cpu: 2, tid: 0 }); t += 4; ev('驱动返回 NETDEV_TX_OK', 'XMIT_RET', 'rc=0', { cpu: 2, tid: 0 }); }
        }
        t += 2;
        if (ep === 'DROP') ev('被队列丢弃', 'DROP', 'reason=QDISC_DROP', { cpu: 2, tid: 0 });
        else ev('Wi-Fi 固件边界', 'BOUNDARY', '之后进入 Wi-Fi 驱动/固件，不在可观测范围', { evidence_level: 3, evidence_label: '辅助旁注', cpu: 2, tid: 0 });
        if (!complete) tl.splice(Math.min(3, tl.length - 1), 0, { rel_us: tl[Math.min(2, tl.length - 1)].rel_us + 0.5, evidence_level: 4, evidence_label: '缺口/未知', stage: 'GAP', title: '证据缺口', detail: 'seq gap：ringbuf 在此区间丢失 1 个事件' });
        return tl;
      };
      const branches = [{ branch_id: 0, label: '主支路', complete: s.complete, completeness: s.completeness, endpoint: s.endpoint, object_chain: [`0x${(sid * 7919).toString(16)}01`], timeline: mk(s.complete, s.endpoint, s.endpoint === 'CONSUME') }];
      const relations = [];
      if (s.branch_count > 1) {
        branches.push({ branch_id: 1, label: 'clone 副本', complete: true, completeness: 'complete', endpoint: 'CONSUME', object_chain: [`0x${(sid * 7919).toString(16)}02`], timeline: mk(true, 'CONSUME', true) });
        relations.push({ rel_type: 'CLONE', src_object_id: `0x${(sid * 7919).toString(16)}01`, dst_object_id: `0x${(sid * 7919).toString(16)}02` });
      }
      const qstates = s.max_sojourn_us > 5000 ? [{ txq: 11, state_op: 'TXQ_STOP→WAKE', start_rel_us: 8, end_rel_us: 8 + s.max_sojourn_us * 0.8, value: '' }] : [];
      return { sample_id: s.sample_id, summary: { uid: s.uid, comm: s.comm, proto: s.proto }, branches, relations, qstates };
    }
    async function handle(path, opts) {
      await sleep(path.includes('prepare') ? 700 : path.includes('stop') ? 900 : 120);
      const p = path.split('?')[0];
      const q = new URLSearchParams(path.split('?')[1] || '');
      switch (p) {
        case '/api/plugins': return {
          ok: true,
          plugins_dir: 'C:\\Users\\demo\\AppData\\Local\\PktPathStudio\\plugins',
          slots: { sock_used: 1, sock_max: 4, classful_used: 0, classful_max: 2, leaf_used: 1, leaf_max: 2, enabled_count: 1, total_count: 1 },
          plugins: [{
            id: 'demo_ext', file: 'demo_ext.json', name: '示例插件：Socket Mark + Netem', version: '1.0',
            description: '演示运行时加载自定义 BTF 字段与叶子队列能力', enabled: true, sock_fields: 1, qdiscs: 1,
            sock_field_specs: [{ struct: 'sock', field: 'sk_mark', size: 4, role: 'tag', label: 'sock_mark', summary: '通过内核 BTF 动态读取 struct sock.sk_mark (4B)，为每个样本附加扩展标签 [sock_mark]' }],
            qdisc_specs: [{ id: 'netem_leaf', name: 'Netem Leaf', kind: 'netem', mode: 'leaf', enqueue_sym: 'netem_enqueue', dequeue_sym: 'netem_dequeue', summary: '追踪自定义叶子队列 NETEM (leaf)：挂钩 netem_enqueue / netem_dequeue，精确测量单包排队驻留耗时' }],
            capabilities: ['通过内核 BTF 动态读取 struct sock.sk_mark (4B)，为每个样本附加扩展标签 [sock_mark]', '追踪自定义叶子队列 NETEM (leaf)：挂钩 netem_enqueue / netem_dequeue，精确测量单包排队驻留耗时'],
          }],
        };
        case '/api/devices': return {
          adb_missing: false, ssh_available: true, available_agents: ['android-arm64', 'linux-x86_64'],
          adb_devices: [{ serial: 'emulator-5554', transport: 'adb', model: 'Pixel 8', product: 'shiba', state: 'device', android_ver: '14', kernel: '6.1.157-android14-11', root_mode: 'adbd-root', agent_ready: true }],
          ssh_targets: [{ id: 'demo-gw', name: 'Linux Gateway (x86_64)', host: '192.0.2.10', port: 22, user: 'root', use_sudo: true }],
          devices: [
            { serial: 'emulator-5554', transport: 'adb', model: 'Pixel 8', product: 'shiba', state: 'device', android_ver: '14', kernel: '6.1.157-android14-11', root_mode: 'adbd-root', agent_ready: true },
            { serial: 'ssh:demo-gw', transport: 'ssh', model: 'Linux Gateway (x86_64)', product: 'Linux SSH', state: 'device', arch: 'x86_64', kernel: '6.8.0-generic', root_mode: 'root', agent_ready: true, ssh_host: '192.0.2.10', ssh_user: 'root', ssh_port: 22 },
          ],
        };
        case '/api/device/prepare': return { ok: true, root_mode: 'adbd-root', kernel: '6.1.157-android14-11', agent_sha256: '9f2c4e1ab3d7' };
        case '/api/device/inspect': return {
          interfaces: [{ name: 'lo', state: 'UNKNOWN', addrs: ['127.0.0.1/8'] }, { name: 'wlan0', state: 'UP', addrs: ['192.0.2.57/24', 'fe80::1/64'] }, { name: 'p2p0', state: 'DOWN', addrs: [] }, { name: 'rmnet_data0', state: 'UP', addrs: ['198.51.100.5/30'] }],
          inspect: { kernel_release: '6.1.157-android14-11', dev: q.get('dev') || 'wlan0', partial_coverage: false, budgets: { estimated_bpf_bytes: 7570000 },
            qdiscs: [
              { kind: 'htb', handle: 0x10000, parent: 0xffffffff, queue_gen: 40 },
              { kind: 'pfifo', handle: 0, parent: 0x10010, queue_gen: 47 },
              { kind: 'fq_codel', handle: 0x120000, parent: 0x10020, queue_gen: 43 },
              { kind: 'sfq', handle: 0x140000, parent: 0x10030, queue_gen: 44 },
            ],
            classes: DEMO_CLASSES,
            adapters: [
              { adapter_id: 'l2_tc_egress_core', name: 'TC/Qdisc & Driver Egress Core', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_qdisc_htb', name: 'HTB Classful Qdisc Adapter', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_qdisc_fq_codel', name: 'fq_codel Leaf Qdisc Adapter', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_qdisc_fifo', name: 'pfifo/bfifo HTB Leaf Adapter', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_qdisc_sfq', name: 'SFQ Leaf Qdisc Adapter', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_tc_classify', name: 'TC Filter & Class Attribution', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_qdisc_pfifo', name: 'pfifo_fast Leaf Adapter', enabled: false, missing_reason: 'not used on target device' },
              { adapter_id: 'l2_qdisc_requeue', name: 'Driver BUSY Requeue Adapter', enabled: false, missing_reason: "symbol 'dev_requeue_skb' absent/inlined" },
              { adapter_id: 'l2_skb_transforms', name: 'SKB Clone & Head Expand', enabled: true, missing_reason: '' },
              { adapter_id: 'l2_txq_qstate', name: 'TXQ Stop/Wake Backpressure', enabled: true, missing_reason: "partial (1/2; symbol 'netif_tx_stop_queue' absent/inlined)" },
              { adapter_id: 'l1_sock_attribution', name: 'Standard Linux Socket Owner', enabled: true, missing_reason: '' },
              { adapter_id: 'l1_sendmsg_profile', name: 'Exact sendmsg TID & Create TS', enabled: false, missing_reason: 'disabled (default profile)' },
            ] },
        };
        case '/api/device/apps': return { apps: [{ pkg: 'com.android.chrome', uid: 10150 }, { pkg: 'com.tencent.mm', uid: 10234 }, { pkg: 'com.ss.android.ugc.aweme', uid: 10276 }, { pkg: 'com.android.shell', uid: 2000 }] };
        case '/api/capture/start': capStart = Date.now(); capMode = opts.body.mode; return { capture_id: 'demo1', status: 'running' };
        case '/api/capture/status': {
          const el = (Date.now() - capStart) / 1000;
          return { active: capStart > 0, capture_id: 'demo1', serial: 'emulator-5554', mode: capMode, dev: 'wlan0', elapsed_sec: el, log_lines: ['[pktpath] BPF programs loaded', '[pktpath] attach kprobes OK', `[pktpath] events=${Math.round(el * 137)} selected=${Math.round(el * 6)}`], last_session_id: '', error: '' };
        }
        case '/api/capture/flush': return { ok: true };
        case '/api/capture/stop': {
          capStart = 0;
          const id = 'demo_' + (sessions.length + 1);
          overviews[id] = makeOverview();
          sessions.unshift({ id, name: `20261124_1832_emulator-5554_wlan0 (${id})`, path: 'C:\\Users\\demo\\AppData\\Local\\PktPathStudio\\sessions\\' + id, created_at: new Date().toISOString(), scope: 'tc-egress', dev: 'wlan0', sample_count: 64 });
          overviews[id].session_path = sessions[0].path;
          return { ok: true, session_id: id, session_path: sessions[0].path, overview: overviews[id] };
        }
        case '/api/sessions': return { sessions };
        case '/api/dialog/pick-folder': return { ok: true, path: 'E:\\demo\\vns_reorder_run' };
        case '/api/dialog/save-file': return { ok: true, cancelled: false, path: 'C:\\Users\\demo\\Downloads\\' + ((opts.body && opts.body.default_name) || 'trace.pcapng') };
        case '/api/dialog/reveal': return { ok: true, path: opts.body && opts.body.path };
        case '/api/app/quit': return { ok: true };
        case '/api/sessions/open': {
          const id = 'demo_open_' + (sessions.length + 1);
          overviews[id] = makeOverview();
          sessions.unshift({ id, name: 'vns_reorder_run', path: opts.body.path, created_at: new Date().toISOString(), scope: 'tc-egress', dev: 'wlan0', sample_count: 64 });
          overviews[id].session_path = opts.body.path;
          return { ok: true, session_id: id, session_path: opts.body.path, overview: overviews[id] };
        }
        case '/api/session/overview': return overviews[q.get('id')] || (overviews[q.get('id')] = makeOverview());
        case '/api/session/sample': return makeSample(overviews[q.get('id')] || makeOverview(), Number(q.get('sample_id')));
        case '/api/session/export-pcapng': return { ok: true, out_path: opts.body && opts.body.out_path, exported_packets: 64 };
        case '/api/session/redact': return { ok: true, out_dir: opts.body.out_dir };
        default: throw new Error('demo: unknown ' + p);
      }
    }
    return { handle };
  })();

  /* =====================================================================
   * 13. Boot
   * ===================================================================== */
  function boot() {
    initTheme();
    bindTooltip();
    bindUI();
    connectAppEvents();
    updateStartBtn();
    refreshDevices(false);
    loadPlugins();
    loadSessions();
    resumeCaptureIfActive();
    S.devTimer = setInterval(() => { if (!S.capturing && !S.quitting && !document.hidden) { refreshDevices(false); loadPlugins(); } }, 6000);
    if (DEMO) {
      toast('演示模式：未连接后端，使用内置示例数据', 'warn');
      if (/[?&]autoload=1\b/.test(location.search)) {
        api('/api/capture/stop', { body: {} }).then((r) => {
          showSession(r.session_id, r.overview);
          if (/[?&]saved=1\b/.test(location.search)) {
            showSavedBar('C:\\Users\\demo\\Downloads\\trace_' + r.session_id + '.pcapng', '已保存：');
          }
          const m = /[?&]sample=(\d+)/.exec(location.search);
          if (m) openSample(m[1]);
        });
      }
    }
  }

  // Expose safe bridge for plugin-center.js & external UI slot plugins
  window.PktPathStudio = {
    api,
    toast,
    esc,
    getState: () => S,
    switchTransport,
    openSample,
    showSession,
    openFolder,
    revealPath,
    showSavedBar,
    refreshDevices,
    loadSessions,
    loadInspect: () => { if (S.serial && S.iface && S.prepState === 'ok') loadInspect(S.serial, S.iface); },
    reloadCurrentSession: () => { if (S.sessionId) showSession(S.sessionId); },
    applyCollectorDefaults: (col) => {
      if (!col) return;
      if (col.default_scope && $('#selScope')) $('#selScope').value = col.default_scope;
      if ($('#chkCapHdr')) $('#chkCapHdr').checked = Number(col.capture_hdr_bytes || 0) > 0;
      if ($('#chkSendmsg')) $('#chkSendmsg').checked = !!col.profile_sendmsg;
      if ($('#chkPartial')) $('#chkPartial').checked = !!col.allow_partial;
      if ($('#chkPlugins')) $('#chkPlugins').checked = col.enable_kernel_exts !== false;
    },
    setCaptureMode: (mode) => {
      S.mode = mode;
      $$('#modeTabs .tab').forEach((x) => x.classList.toggle('active', x.dataset.mode === mode));
      $$('.tab-pane').forEach((p) => { p.hidden = p.dataset.pane !== mode; });
      updateStartBtn();
    },
    applyModeDefaults: (oneshotCfg, daemonCfg) => {
      if (oneshotCfg) {
        if (oneshotCfg.default_sample && $('#segSample')) { setSeg($('#segSample'), oneshotCfg.default_sample); S.sample = oneshotCfg.default_sample; }
        if (oneshotCfg.default_duration_sec && $('#segDuration')) {
          S.duration = Number(oneshotCfg.default_duration_sec) || 10;
          setSeg($('#segDuration'), String(S.duration));
        }
      }
      if (daemonCfg) {
        if (daemonCfg.default_threshold_ms && $('#inpThreshold')) {
          $('#inpThreshold').value = daemonCfg.default_threshold_ms;
          if ($('#thrLabel')) $('#thrLabel').textContent = daemonCfg.default_threshold_ms;
        }
        if (daemonCfg.default_pre_sec !== undefined && $('#inpPre')) $('#inpPre').value = daemonCfg.default_pre_sec;
        if (daemonCfg.default_post_sec !== undefined && $('#inpPost')) $('#inpPost').value = daemonCfg.default_post_sec;
      }
    },
    _onSessionRendered: null,
    _onTransportChanged: null,
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
