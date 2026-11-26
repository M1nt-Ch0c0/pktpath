import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  uiThemePlugin,
  normalizeThemeConfig,
  DEFAULT_UI_THEME_CONFIG,
  SUPPORTED_THEME_MODES,
  SUPPORTED_THEME_ACCENTS,
  SUPPORTED_THEME_DENSITIES,
  type UiThemeService,
} from '../src/plugins/ui/theme.ts';

test('normalizeThemeConfig validates and clamps all fields safely', () => {
  assert.deepEqual(normalizeThemeConfig(undefined), DEFAULT_UI_THEME_CONFIG);
  assert.deepEqual(normalizeThemeConfig(null), DEFAULT_UI_THEME_CONFIG);
  assert.deepEqual(
    normalizeThemeConfig({ mode: 'dark', accent: 'violet', density: 'compact', font_scale: 112.4 }),
    { mode: 'dark', accent: 'violet', density: 'compact', font_scale: 112 },
  );
  assert.deepEqual(
    normalizeThemeConfig({ mode: 'neon', accent: 'invalid', density: 'tiny', font_scale: 40 }),
    { mode: 'light', accent: 'blue', density: 'comfortable', font_scale: 85 },
  );
  assert.deepEqual(
    normalizeThemeConfig({ font_scale: 999 }),
    { mode: 'light', accent: 'blue', density: 'comfortable', font_scale: 120 },
  );
  assert.deepEqual(
    normalizeThemeConfig({ font_scale: 'NaN' }),
    { mode: 'light', accent: 'blue', density: 'comfortable', font_scale: 100 },
  );
});

test('uiThemePlugin metadata and schema conform to Wave 1 contract', () => {
  assert.equal(uiThemePlugin.meta.id, 'builtin.ui.theme');
  assert.equal(uiThemePlugin.meta.category, 'ui');
  assert.equal(uiThemePlugin.meta.builtin, true);
  assert.deepEqual(uiThemePlugin.meta.capabilities, ['ui.theme']);
  assert.deepEqual(uiThemePlugin.meta.provides, ['ui.theme']);
  const keys = uiThemePlugin.schema.fields.map((f) => f.key);
  assert.deepEqual(keys, ['mode', 'accent', 'density', 'font_scale']);
});

test('uiThemePlugin.apply registers ui.theme service and ui.slot extension', () => {
  const services = new Map<string, unknown>();
  const extensions: Array<{ point: string; value: unknown }> = [];
  const fakeCtx: any = {
    pluginId: 'builtin.ui.theme',
    provide: (name: string, impl: unknown) => { services.set(name, impl); },
    registerExtension: (point: string, value: unknown) => { extensions.push({ point, value }); },
  };
  uiThemePlugin.apply(fakeCtx, { mode: 'dark', accent: 'emerald', density: 'compact', font_scale: 105 });

  const svc = services.get('ui.theme') as UiThemeService;
  assert.ok(svc);
  assert.deepEqual(svc.getConfig(), { mode: 'dark', accent: 'emerald', density: 'compact', font_scale: 105 });
  assert.deepEqual(svc.supportedModes, SUPPORTED_THEME_MODES);
  assert.deepEqual(svc.supportedAccents, SUPPORTED_THEME_ACCENTS);
  assert.deepEqual(svc.supportedDensities, SUPPORTED_THEME_DENSITIES);

  assert.equal(extensions.length, 1);
  assert.equal(extensions[0].point, 'ui.slot');
  assert.deepEqual(extensions[0].value, {
    id: 'ui.theme',
    plugin_id: 'builtin.ui.theme',
    slot: 'appbar.actions',
    name: '主题切换',
    mode: 'dark',
    accent: 'emerald',
    density: 'compact',
    font_scale: 105,
  });
});

test('uiThemePlugin lifecycle on real CordisHost (register, updateConfig, persist, toggle, resetConfig)', async (t) => {
  const localHostPath = path.resolve(import.meta.dirname, '../src/kernel/host.ts');
  const hostPath = process.env.PKTPATH_CORDIS_HOST_MODULE
    ? path.resolve(process.env.PKTPATH_CORDIS_HOST_MODULE)
    : localHostPath;

  if (!fs.existsSync(hostPath)) {
    t.skip('CordisHost not present in standalone frontend worktree (set PKTPATH_CORDIS_HOST_MODULE to run)');
    return;
  }

  const { CordisHost } = await import(pathToFileURL(hostPath).href);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pktpath-ui-theme-test-'));
  const paths = {
    appDir: tmpDir,
    sessionsRoot: path.join(tmpDir, 'sessions'),
    pluginsDir: path.join(tmpDir, 'plugins'),
    exportsDir: path.join(tmpDir, 'exports'),
    collectorsDir: path.join(tmpDir, 'collectors'),
    webDir: path.resolve(import.meta.dirname, '../web'),
  };

  const host = new CordisHost(paths, 'cordis-wave1');
  try {
    host.registerBuiltin(uiThemePlugin);
    await host.start();

    let snap = host.snapshot();
    assert.equal(snap.active_plugins, 1);
    const pluginItem = snap.plugins.find((p: any) => p.id === 'builtin.ui.theme');
    assert.ok(pluginItem);
    assert.equal(pluginItem.enabled, true);
    assert.equal(pluginItem.status, 'active');
    assert.equal(snap.ui_slots.length, 1);
    assert.equal((snap.ui_slots[0] as any).mode, 'light');

    // Update config & verify persistence + clamping
    const upd = await host.updateConfig('builtin.ui.theme', {
      mode: 'dark',
      accent: 'violet',
      density: 'compact',
      font_scale: 150,
    });
    assert.equal(upd.ok, true);
    assert.equal((upd.state.ui_slots[0] as any).mode, 'dark');
    assert.equal((upd.state.ui_slots[0] as any).accent, 'violet');
    assert.equal((upd.state.ui_slots[0] as any).font_scale, 120);

    const persisted = JSON.parse(fs.readFileSync(path.join(tmpDir, 'kernel-config.json'), 'utf-8'));
    assert.equal(persisted.configs['builtin.ui.theme'].mode, 'dark');

    // Disable removes ui.slot cleanly while keeping plugin visible in catalog
    const dis = await host.toggle('builtin.ui.theme', false);
    assert.equal(dis.ok, true);
    assert.equal(dis.state.ui_slots.length, 0);
    const disItem = dis.state.plugins.find((p: any) => p.id === 'builtin.ui.theme');
    assert.equal(disItem.enabled, false);
    assert.equal(disItem.status, 'disabled');

    // Re-enable restores persisted dark config
    const en = await host.toggle('builtin.ui.theme', true);
    assert.equal(en.ok, true);
    assert.equal(en.state.ui_slots.length, 1);
    assert.equal((en.state.ui_slots[0] as any).mode, 'dark');

    // Reset config restores light default
    const rst = await host.resetConfig('builtin.ui.theme');
    assert.equal(rst.ok, true);
    assert.equal((rst.state.ui_slots[0] as any).mode, 'light');
    assert.equal((rst.state.ui_slots[0] as any).accent, 'blue');
  } finally {
    await host.shutdown();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
