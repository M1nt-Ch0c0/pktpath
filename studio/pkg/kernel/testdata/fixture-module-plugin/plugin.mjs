export async function setup(ctx) {
  ctx.effect(() => async () => {
    await new Promise((resolve) => setTimeout(resolve, 80));
  });
}

export async function analyze(input) {
  const samples = Array.isArray(input.overview?.samples) ? input.overview.samples : [];
  const alerts = input.overview?.stats?.quality_alerts;
  const hasError = Array.isArray(alerts) && alerts.some((a) => a && a.severity === 'error');
  return {
    insights: [
      {
        id: 'fixture.sample-count',
        plugin_id: input.plugin_id,
        plugin_name: 'Fixture module plugin',
        severity: hasError ? 'critical' : 'info',
        title: 'sample count',
        summary: String(samples.length),
        sample_ids: samples.map((s) => s.sample_id).filter((id) => id != null),
      },
    ],
    kpis: [
      {
        plugin_id: input.plugin_id,
        label: 'samples',
        value: String(samples.length),
        tone: 'ok',
      },
    ],
    notes: ['fixture-analyze'],
  };
}

export async function exportSession(input) {
  const { writeFile } = await import('node:fs/promises');
  await writeFile(input.out_path, JSON.stringify({
    ok: true,
    session_id: input.session_id,
    note: 'fixture-export',
  }, null, 2));
  return { ok: true, out_path: input.out_path, summary: 'wrote fixture export' };
}
