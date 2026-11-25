import { createHash, randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export function parseLossless(raw) {
  return JSON.parse(raw, (_key, value, context) => {
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) {
      if (!context?.source || !/^-?\d+$/.test(context.source)) throw new Error('unsafe numeric token: Node22+ source-aware JSON required');
      return BigInt(context.source);
    }
    return value;
  });
}

export function analyze(req) {
  if (req?.action !== 'analyze' || req.plugin_id !== 'community.queue-tail' || req.analyzer_id !== 'community.queue-tail.summary') throw new Error('unsupported analyzer request');
  if (!Array.isArray(req.overview?.samples)) throw new Error('overview.samples must be an array');
  const threshold = req.config?.threshold_us ?? 5000;
  if (typeof threshold !== 'number' || !Number.isFinite(threshold) || threshold < 0 || threshold > 1e9) throw new Error('invalid threshold_us');
  const rows = req.overview.samples;
  if (rows.some(r => !r || typeof r !== 'object' || Array.isArray(r))) throw new Error('invalid sample row');
  const positive = rows.map(r => r.max_sojourn_us).filter(v => typeof v === 'number' && Number.isFinite(v) && v > 0 && v <= Number.MAX_SAFE_INTEGER).sort((a,b) => a-b);
  const incomplete = rows.filter(r => r.complete !== true).length;
  const above = positive.filter(v => v > threshold).length;
  const p95 = positive.length ? positive[Math.ceil(positive.length * .95) - 1] : null;
  const coverage = `${positive.length}/${rows.length}`;
  const out = {insights: [{id:'community.queue-tail.coverage',severity:incomplete ? 'info':'ok',title:'重建样本覆盖说明',summary:`${rows.length}个样本，${incomplete}个未标记完整；${rows.length-positive.length}个零值/缺失/不适用驻留不进入正值尾延迟统计。未知不等于真实0。`,metric:coverage}],kpis:[{label:'正值驻留覆盖',value:coverage,sub:'零/缺失不计入分位数；非流量总量'},{label:'外部JS驻留p95',value:p95 === null ? 'unknown' : String(p95),sub:'us；仅本次Go重建overview中的正值样本'},{label:'驻留超阈样本',value:String(above),sub:`正值驻留 > ${threshold} us`}],notes:[]};
  if (positive.length) out.insights.push({id:'community.queue-tail.tail',severity:above ? 'warn':'info',title:'正值队列驻留尾延迟',summary:`正值样本${positive.length}个，p95=${p95} us，${above}个超过${threshold} us。不是端到端SLA/根因结论，不提升Go证据等级。`,metric:String(p95)});
  return out; // sample IDs intentionally never round-trip through JS numbers.
}

async function main() {
  process.stdin.setEncoding('utf8'); // streaming decoder preserves split multibyte text
  let raw='';
  for await (const chunk of process.stdin) { raw+=chunk; if (Buffer.byteLength(raw)>64*1024*1024) throw new Error('input exceeds 64 MiB'); }
  const req=parseLossless(raw);const out=analyze(req);
  const digest=createHash('sha256').update(raw).digest('hex');
  out.notes.push(`queue-tail-js pid=${process.pid} ppid=${process.ppid} node=${process.version} input_sha256=${digest}`);
  const output=JSON.stringify(out);
  // Explicit opt-in evidence only. Normal plugin performs no filesystem I/O.
  const audit=process.env.PKTPATH_QUEUE_TAIL_AUDIT_DIR;
  if (audit) {const stem=join(audit,`${process.pid}-${randomUUID()}`);await writeFile(stem+'.input.json',raw,{flag:'wx',mode:0o600});await writeFile(stem+'.output.json',output,{flag:'wx',mode:0o600});}
  process.stdout.write(output+'\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err=>{process.stderr.write(`queue-tail: ${err.message}\n`);process.exitCode=1;});
}
