export function setup(_ctx, _config) {
  // Optional initialization hook when Studio loads this plugin.
}

export async function analyze(input) {
  const packets = Array.isArray(input?.packets) ? input.packets : [];
  let matched = 0;
  for (const pkt of packets) {
    const events = Array.isArray(pkt?.events) ? pkt.events : [];
    for (const ev of events) {
      if (ev?.stage === 'rx_ingress') {
        matched += 1;
      }
    }
  }
  return {
    summary: `示例探针共观察到 ${matched} 条收包入口事件。`,
    kpis: [
      { label: '收包入口事件数', value: String(matched), tone: matched > 0 ? 'ok' : 'default' },
    ],
    insights: matched === 0
      ? [{ severity: 'info', title: '未观测到收包入口事件', detail: '请确认已在插件设置中开启探针并在目标设备上运行采集。' }]
      : [],
  };
}
