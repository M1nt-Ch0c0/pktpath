export async function analyze() {
  return { insights: [{ id: "x", plugin_id: "community.analyzer.bad-severity", plugin_name: "Bad", severity: "error", title: "no", summary: "invalid severity" }], kpis: [], notes: [] };
}
