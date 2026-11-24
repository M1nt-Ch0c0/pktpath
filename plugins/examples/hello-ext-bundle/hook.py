#!/usr/bin/env python3
"""Example out-of-process JSON-over-stdio hook for PktPath Studio v2.0.

Handles both `analyze` and `export` actions cleanly via stdin/stdout JSON.
"""

from __future__ import annotations

import json
import os
import sys


def handle_analyze(req: dict) -> dict:
    cfg = req.get("config") or {}
    budget_ms = float(cfg.get("latency_budget_ms") or 5.0)
    ov = req.get("overview") or {}
    samples = ov.get("samples") or []
    total = len(samples)
    if total == 0:
        return {"insights": [], "kpis": []}

    breached = []
    for s in samples:
        ms = float(s.get("max_sojourn_us") or 0.0) / 1000.0
        if ms > budget_ms:
            breached.append((ms, int(s.get("sample_id") or 0)))
    breached.sort(reverse=True)
    passed = total - len(breached)
    pass_rate = (passed / total) * 100.0

    sev = "ok" if len(breached) == 0 else ("warn" if pass_rate >= 90.0 else "critical")
    tone = "ok" if sev == "ok" else ("warn" if sev == "warn" else "bad")
    return {
        "insights": [
            {
                "id": "sla.summary",
                "severity": sev,
                "title": f"SLA 达标审计（预算 ≤ {budget_ms:g} ms）",
                "summary": (
                    f"共审计 {total} 个样本：{passed} 个达标，{len(breached)} 个超预算"
                    f"（达标率 {pass_rate:.1f}%）。本洞察由外部插件 example.sla-auditor 实时产出。"
                ),
                "metric": f"达标率 {pass_rate:.1f}%",
                "sample_ids": [sid for _, sid in breached[:6]],
            }
        ],
        "kpis": [
            {
                "label": f"SLA 达标率 (≤{budget_ms:g}ms)",
                "value": f"{pass_rate:.1f}%",
                "sub": f"{passed}/{total} 达标 · 外部插件",
                "tone": tone,
            }
        ],
    }


def handle_export(req: dict) -> dict:
    cfg = req.get("config") or {}
    budget_ms = float(cfg.get("latency_budget_ms") or 5.0)
    title = str(cfg.get("report_title") or "PktPath SLA 达标审计报告")
    out_path = str(req.get("out_path") or "")
    sess_id = str(req.get("session_id") or "")
    ov = req.get("overview") or {}
    samples = ov.get("samples") or []

    breached = [
        (float(s.get("max_sojourn_us") or 0.0) / 1000.0, s)
        for s in samples
        if float(s.get("max_sojourn_us") or 0.0) / 1000.0 > budget_ms
    ]
    breached.sort(key=lambda x: x[0], reverse=True)
    total = len(samples)
    passed = total - len(breached)
    rate = (passed / total * 100.0) if total else 100.0

    lines = [
        f"# {title}",
        "",
        f"- 会话 ID: `{sess_id}`",
        f"- SLA 预算阈值: **{budget_ms:g} ms**",
        f"- 总样本数: **{total}** · 达标: **{passed}** · 违约: **{len(breached)}** · 达标率: **{rate:.2f}%**",
        "",
    ]
    if breached:
        lines.append("## Top 违约样本")
        lines.append("")
        lines.append("| SampleID | 进程 | 协议 | 驻留耗时 (ms) | 终点 | 路径 |")
        lines.append("|---:|---|---|---:|---|---|")
        for ms, s in breached[:25]:
            lines.append(
                f"| {s.get('sample_id')} | {s.get('comm') or '-'} | {s.get('proto') or '-'} | "
                f"{ms:.3f} | {s.get('endpoint') or '-'} | `{s.get('path_sig') or ''}` |"
            )
    else:
        lines.append("所有样本均满足 SLA 预算，无违约记录。")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return {
        "ok": True,
        "out_path": out_path,
        "summary": f"外部插件已生成 SLA 报告（达标率 {rate:.1f}%，违约 {len(breached)} 条）",
        "details": {"total": total, "breached": len(breached), "pass_rate": round(rate, 2)},
    }


def main() -> int:
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {}
    action = req.get("action")
    if action == "analyze":
        res = handle_analyze(req)
    elif action == "export":
        res = handle_export(req)
    else:
        res = {"ok": False, "error": f"unsupported action: {action}"}
    sys.stdout.write(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
