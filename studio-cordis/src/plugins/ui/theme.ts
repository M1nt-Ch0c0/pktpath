import type { BuiltinPlugin } from '../../kernel/types.ts';

export type ThemeMode = 'light' | 'dark';
export type ThemeAccent = 'blue' | 'emerald' | 'violet' | 'amber' | 'rose';
export type ThemeDensity = 'comfortable' | 'compact';

export interface UiThemeConfig {
  mode: ThemeMode;
  accent: ThemeAccent;
  density: ThemeDensity;
  font_scale: number;
}

export interface UiThemeService {
  getConfig(): UiThemeConfig;
  readonly supportedModes: readonly ThemeMode[];
  readonly supportedAccents: readonly ThemeAccent[];
  readonly supportedDensities: readonly ThemeDensity[];
}

export const SUPPORTED_THEME_MODES: readonly ThemeMode[] = ['light', 'dark'];
export const SUPPORTED_THEME_ACCENTS: readonly ThemeAccent[] = ['blue', 'emerald', 'violet', 'amber', 'rose'];
export const SUPPORTED_THEME_DENSITIES: readonly ThemeDensity[] = ['comfortable', 'compact'];

export const DEFAULT_UI_THEME_CONFIG: Readonly<UiThemeConfig> = Object.freeze({
  mode: 'light',
  accent: 'blue',
  density: 'comfortable',
  font_scale: 100,
});

export function normalizeThemeConfig(raw: Record<string, unknown> | null | undefined): UiThemeConfig {
  const src = raw && typeof raw === 'object' ? raw : {};
  const mode: ThemeMode = src.mode === 'dark' ? 'dark' : 'light';
  const rawAccent = typeof src.accent === 'string' ? src.accent : '';
  const accent: ThemeAccent = (SUPPORTED_THEME_ACCENTS as readonly string[]).includes(rawAccent)
    ? (rawAccent as ThemeAccent)
    : 'blue';
  const density: ThemeDensity = src.density === 'compact' ? 'compact' : 'comfortable';
  const parsedScale = Number(src.font_scale);
  const font_scale = Number.isFinite(parsedScale)
    ? Math.max(85, Math.min(120, Math.round(parsedScale)))
    : 100;
  return { mode, accent, density, font_scale };
}

export const uiThemePlugin: BuiltinPlugin = {
  meta: {
    id: 'builtin.ui.theme',
    name: '界面主题 (Theme)',
    version: '1.0.0',
    description: '控制工作台明/暗色主题、强调色、紧凑度与字号缩放，支持在插件中心启停并持久化配置。',
    category: 'ui',
    icon: 'palette',
    builtin: true,
    capabilities: ['ui.theme'],
    provides: ['ui.theme'],
    tags: ['ui', 'theme'],
  },
  schema: {
    fields: [
      {
        key: 'mode',
        label: '外观主题',
        type: 'select',
        default: 'light',
        description: '切换工作台浅色或深色界面。',
        options: [
          { value: 'light', label: '浅色 (Light)' },
          { value: 'dark', label: '深色 (Dark)' },
        ],
      },
      {
        key: 'accent',
        label: '强调色',
        type: 'select',
        default: 'blue',
        description: '主按钮与高亮元素配色。',
        options: [
          { value: 'blue', label: '默认蓝 (Blue)' },
          { value: 'emerald', label: '翡翠绿 (Emerald)' },
          { value: 'violet', label: '紫罗兰 (Violet)' },
          { value: 'amber', label: '琥珀黄 (Amber)' },
          { value: 'rose', label: '玫瑰红 (Rose)' },
        ],
      },
      {
        key: 'density',
        label: '排版密度',
        type: 'select',
        default: 'comfortable',
        description: '调整列表与工具条间距。',
        options: [
          { value: 'comfortable', label: '舒适 (Comfortable)' },
          { value: 'compact', label: '紧凑 (Compact)' },
        ],
      },
      {
        key: 'font_scale',
        label: '字号缩放 (%)',
        type: 'number',
        default: 100,
        min: 85,
        max: 120,
        description: '工作台基础字号百分比（85–120）。',
      },
    ],
  },
  apply(ctx, cfg) {
    const normalized = normalizeThemeConfig(cfg);
    const service: UiThemeService = {
      getConfig: () => ({ ...normalized }),
      supportedModes: SUPPORTED_THEME_MODES,
      supportedAccents: SUPPORTED_THEME_ACCENTS,
      supportedDensities: SUPPORTED_THEME_DENSITIES,
    };

    ctx.provide('ui.theme', service);
    ctx.registerExtension('ui.slot', {
      id: 'ui.theme',
      plugin_id: 'builtin.ui.theme',
      slot: 'appbar.actions',
      name: '主题切换',
      mode: normalized.mode,
      accent: normalized.accent,
      density: normalized.density,
      font_scale: normalized.font_scale,
    });
  },
};
