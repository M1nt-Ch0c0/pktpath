/* External UI Slot Widget for example.sla-auditor */
(function () {
  if (!window.PktPathUI) return;
  window.PktPathUI.registerSlot('example.sla-auditor.banner', function (container, ctx) {
    const ov = ctx.overview;
    if (!ov || !Array.isArray(ov.samples) || ov.samples.length === 0) {
      container.innerHTML = '';
      return;
    }
    const plug = ((ctx.kernelState && ctx.kernelState.plugins) || []).find((p) => p.meta.id === 'example.sla-auditor');
    const budgetMs = Number((plug && plug.config && plug.config.latency_budget_ms) || 5);
    const total = ov.samples.length;
    const passed = ov.samples.filter((s) => (Number(s.max_sojourn_us || 0) / 1000) <= budgetMs).length;
    const pct = total ? Math.round((passed / total) * 1000) / 10 : 100;
    container.innerHTML = `
      <div class="sla-widget">
        <span class="sla-widget-badge">🎯 外部插件 UI 插槽</span>
        <span class="sla-widget-text">SLA 预算 ≤ <b>${budgetMs} ms</b>：<b>${passed}/${total}</b> 达标 (<b>${pct}%</b>)</span>
        <div class="sla-widget-bar"><div class="sla-widget-fill" style="width:${pct}%"></div></div>
      </div>`;
  });
})();
