import test from 'node:test';
import assert from 'node:assert/strict';
import {analyze,parseLossless} from './analyze.mjs';
const req=samples=>({action:'analyze',plugin_id:'community.queue-tail',analyzer_id:'community.queue-tail.summary',config:{threshold_us:10},overview:{samples}});
test('data-driven tail and coverage, zero is not measured',()=>{const a=analyze(req([{complete:true,max_sojourn_us:1},{complete:false,max_sojourn_us:100},{complete:true,max_sojourn_us:0}]));assert.equal(a.kpis[1].value,'100');assert.equal(a.kpis[2].value,'1');assert.equal(a.kpis[0].value,'2/3');assert.equal(a.insights[1].severity,'warn');assert.equal(analyze(req([{complete:true,max_sojourn_us:1}])).kpis[2].value,'0');});
test('empty/missing positive measurements stay unknown',()=>{assert.equal(analyze(req([])).kpis[1].value,'unknown');assert.equal(analyze(req([{max_sojourn_us:0}])).insights.length,1);});
test('u64 max is parsed exactly and never emitted rounded',()=>{const q=parseLossless('{"sample_id":18446744073709551615}');assert.equal(q.sample_id,18446744073709551615n);const out=analyze(req([{...q,complete:true,max_sojourn_us:3}]));assert.ok(!JSON.stringify(out).includes('184467'));});
test('invalid request/config/input fails',()=>{assert.throws(()=>analyze({}));const r=req([]);r.config.threshold_us=-1;assert.throws(()=>analyze(r));assert.throws(()=>parseLossless('{bad'));assert.throws(()=>analyze(req([null])));});
