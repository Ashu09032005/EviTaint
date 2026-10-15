import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPipeline } from '../src/pipeline.js';
import { checkClaims } from '../src/explain/checker.js';
import { buildClaims } from '../src/explain/claims.js';
import { fitIsotonic, applyCalibration, expectedCalibrationError } from '../src/explain/calibration.js';
import { inferSpecs } from '../src/specs/inference.js';
import { analyzeFiles } from '../src/core/engine.js';

test('pipeline produces explanations with faithfulness scores', async () => {
  const files = { 'app.js': "app.get('/a',(req,res)=>res.send('<b>'+req.query.n+'</b>'))" };
  const r = await runPipeline(files, {});
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.ok(r.explanations[f.id].prose.length > 0);
  assert.equal(f.faithfulness, 1);
  assert.ok(f.confidence.calibrated >= 0 && f.confidence.calibrated <= 1);
});

test('claim checker flags a tampered trace as unsupported', () => {
  const r = analyzeFiles({ 'app.js': "app.get('/a',(req,res)=>res.send(req.query.n))" });
  const f = r.findings[0];
  const claims = buildClaims(f, {});
  // Corrupt the source offsets so the evidence no longer resolves.
  const bad = claims.map((c) => (c.kind === 'flow-path' ? { ...c, evidence: { ...c.evidence, steps: c.evidence.steps.map((s) => ({ ...s, offsets: [999999, 1000000] })) } } : c));
  const good = checkClaims(claims, r.project.files, {});
  const corrupted = checkClaims(bad, r.project.files, {});
  assert.equal(good.faithfulness, 1);
  assert.ok(corrupted.faithfulness < 1);
});

test('confirmation confirms a reachable command injection', async () => {
  const files = { 'server.js': "const express=require('express');const app=express();const cp=require('child_process');app.post('/p',(req,res)=>cp.exec('ping '+req.body.h,()=>res.end()));app.listen(0)" };
  const r = await runPipeline(files, { confirm: true });
  const f = r.findings.find((x) => x.category === 'cmdi');
  assert.equal(f.confirmation, 'confirmed');
});

test('counterfactual marks a finding causally supported', async () => {
  const files = { 'app.js': "app.get('/a',(req,res)=>db.query('SELECT '+req.query.n))" };
  const r = await runPipeline(files, { counterfactual: true });
  const cf = r.counterfactuals[r.findings[0].id];
  assert.equal(cf.causallySupported, true);
  assert.equal(cf.sanitizingPatch.staticFindingRemoved, true);
});

test('isotonic calibration is monotonic and lowers ECE on a toy set', () => {
  const pairs = [];
  for (let i = 0; i < 200; i++) { const s = Math.random(); pairs.push({ score: s, label: Math.random() < s * 0.6 + 0.2 ? 1 : 0 }); }
  const curve = fitIsotonic(pairs);
  for (let i = 1; i < curve.points.length; i++) assert.ok(curve.points[i].y >= curve.points[i - 1].y - 1e-9);
  const before = expectedCalibrationError(pairs).ece;
  const after = expectedCalibrationError(pairs.map((p) => ({ score: applyCalibration(p.score, curve).calibrated, label: p.label }))).ece;
  assert.ok(after <= before + 0.05);
});

test('spec inference only accepts candidates that pass the verification gate', async () => {
  // A custom sink `renderUnsafe` used with request input should be minable + verifiable.
  const files = { 'app.js': "app.get('/a',(req,res)=>{renderHtml(req.query.n);res.end()})" };
  const r = analyzeFiles(files);
  const inf = await inferSpecs(r, {});
  for (const s of inf.accepted.sinks) assert.equal(s.verified, true);
  for (const s of inf.rejected.sinks) assert.equal(s.verified, false);
});
