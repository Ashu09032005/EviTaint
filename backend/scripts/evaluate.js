#!/usr/bin/env node
/**
 * EviTaint evaluation driver.
 *
 * For every benchmark app with a label file it computes, against line-level
 * ground truth:
 *   - detection precision / recall / F1 (overall and per category)
 *   - bootstrap 95% CIs for F1
 *   - trace quality (fraction of TP findings whose trace reaches the labeled sink)
 *   - explanation faithfulness (mean over findings)
 *   - confirmation and counterfactual rates
 *   - calibration (ECE, Brier) over all findings using TP/FP as the label
 * It repeats the run for a set of ABLATIONS so each contribution is isolated.
 *
 * Usage: node scripts/evaluate.js [--out results.json] [--confirm]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readProject } from '../src/core/project.js';
import { runPipeline } from '../src/pipeline.js';
import { expectedCalibrationError, brierScore } from '../src/explain/calibration.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BENCH = path.join(__dirname, '..', '..', 'benchmark');

const ABLATIONS = {
  full: {},
  'no-interprocedural': { interprocedural: false },
  'no-sanitizers': { sanitizers: false },
  'no-kill-on-reassign': { killOnReassign: false },
  'no-template-literals': { templateLiterals: false },
  'prototype-equivalent': { interprocedural: false, sanitizers: false, killOnReassign: false, templateLiterals: false },
};

function loadApps() {
  const apps = [];
  const labelsDir = path.join(BENCH, 'labels');
  for (const lf of fs.readdirSync(labelsDir)) {
    if (!lf.endsWith('.json')) continue;
    const label = JSON.parse(fs.readFileSync(path.join(labelsDir, lf), 'utf8'));
    const appDir = path.join(BENCH, 'apps', label.app);
    if (!fs.existsSync(appDir)) continue;
    const { files } = readProject(appDir);
    apps.push({ label, files });
  }
  return apps;
}

const key = (f, l) => `${f}:${l}`;

function scoreApp(report, label) {
  const pos = new Map(label.positives.map((p) => [key(p.file, p.line), p]));
  const neg = new Map(label.negatives.map((n) => [key(n.file, n.line), n]));
  const matched = new Set();
  const perCat = {};
  const cat = (c) => (perCat[c] = perCat[c] || { tp: 0, fp: 0, fn: 0 });
  const calibrationPairs = [];
  let traceOk = 0; let traceTotal = 0;

  for (const f of report.findings) {
    const k = key(f.file, f.line);
    const isTP = pos.has(k) && (pos.get(k).category === f.category);
    const anyPos = pos.has(k);
    calibrationPairs.push({ score: f.confidence.calibrated, label: isTP ? 1 : 0 });
    if (isTP) { cat(f.category).tp++; matched.add(k); traceTotal++; if (f.trace.some((s) => s.kind === 'sink' && s.line === f.line)) traceOk++; }
    else if (neg.has(k) || !anyPos) { cat(f.category).fp++; }
    else { cat(f.category).fp++; } // reported at a positive line but wrong category
  }
  for (const [k, p] of pos) if (!matched.has(k)) cat(p.category).fn++;

  return { perCat, calibrationPairs, traceOk, traceTotal, findings: report.findings.length };
}

function prf(tp, fp, fn) {
  const p = tp + fp ? tp / (tp + fp) : (tp ? 1 : 1);
  const r = tp + fn ? tp / (tp + fn) : 1;
  const f1 = p + r ? (2 * p * r) / (p + r) : 0;
  return { precision: Number(p.toFixed(3)), recall: Number(r.toFixed(3)), f1: Number(f1.toFixed(3)), tp, fp, fn };
}

function aggregate(perAppCats) {
  const tot = {};
  for (const perCat of perAppCats) for (const [c, v] of Object.entries(perCat)) { tot[c] = tot[c] || { tp: 0, fp: 0, fn: 0 }; tot[c].tp += v.tp; tot[c].fp += v.fp; tot[c].fn += v.fn; }
  const byCat = {}; let TP = 0; let FP = 0; let FN = 0;
  for (const [c, v] of Object.entries(tot)) { byCat[c] = prf(v.tp, v.fp, v.fn); TP += v.tp; FP += v.fp; FN += v.fn; }
  return { micro: prf(TP, FP, FN), byCategory: byCat };
}

function bootstrapF1(pairsPerFinding, iters = 1000) {
  // pairsPerFinding: array of {tp,fp,fn} unit contributions is hard; approximate
  // CI by resampling the per-item outcome vector.
  const items = pairsPerFinding;
  if (!items.length) return null;
  const f1s = [];
  for (let i = 0; i < iters; i++) {
    let tp = 0; let fp = 0; let fn = 0;
    for (let j = 0; j < items.length; j++) { const it = items[Math.floor(Math.random() * items.length)]; tp += it.tp; fp += it.fp; fn += it.fn; }
    const p = tp + fp ? tp / (tp + fp) : 1; const r = tp + fn ? tp / (tp + fn) : 1;
    f1s.push(p + r ? (2 * p * r) / (p + r) : 0);
  }
  f1s.sort((a, b) => a - b);
  return { lo: Number(f1s[Math.floor(iters * 0.025)].toFixed(3)), hi: Number(f1s[Math.floor(iters * 0.975)].toFixed(3)) };
}

async function run() {
  const args = process.argv.slice(2);
  const confirm = args.includes('--confirm');
  const outIdx = args.indexOf('--out');
  const outFile = outIdx >= 0 ? args[outIdx + 1] : path.join(BENCH, 'evaluation_results.json');
  const apps = loadApps();
  const results = { generatedAt: new Date().toISOString(), confirm, apps: apps.map((a) => a.label.app), ablations: {} };

  for (const [name, opt] of Object.entries(ABLATIONS)) {
    const perAppCats = []; const calib = []; const faiths = []; const units = [];
    let traceOk = 0; let traceTotal = 0; let confirmed = 0; let causally = 0; let totalFindings = 0;
    for (const { label, files } of apps) {
      // eslint-disable-next-line no-await-in-loop
      const report = await runPipeline(files, { ...opt, confirm: confirm && name === 'full', counterfactual: confirm && name === 'full', dynamicCounterfactual: false });
      const s = scoreApp(report, label);
      perAppCats.push(s.perCat); calib.push(...s.calibrationPairs);
      traceOk += s.traceOk; traceTotal += s.traceTotal; totalFindings += s.findings;
      for (const f of report.findings) { if (f.faithfulness != null) faiths.push(f.faithfulness); if (f.confirmation === 'confirmed') confirmed++; if (f.counterfactual === true) causally++; }
      for (const v of Object.values(s.perCat)) { for (let i = 0; i < v.tp; i++) units.push({ tp: 1, fp: 0, fn: 0 }); for (let i = 0; i < v.fp; i++) units.push({ tp: 0, fp: 1, fn: 0 }); for (let i = 0; i < v.fn; i++) units.push({ tp: 0, fp: 0, fn: 1 }); }
    }
    const agg = aggregate(perAppCats);
    results.ablations[name] = {
      detection: agg,
      f1CI: bootstrapF1(units),
      traceQuality: traceTotal ? Number((traceOk / traceTotal).toFixed(3)) : null,
      meanFaithfulness: faiths.length ? Number((faiths.reduce((a, b) => a + b, 0) / faiths.length).toFixed(3)) : null,
      calibration: { ...expectedCalibrationError(calib), brier: brierScore(calib) },
      ...(name === 'full' && confirm ? { confirmedRate: Number((confirmed / Math.max(1, totalFindings)).toFixed(3)), causallySupportedRate: Number((causally / Math.max(1, totalFindings)).toFixed(3)) } : {}),
      totalFindings,
    };
  }

  fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  printReport(results);
  console.log(`\nraw results -> ${outFile}`);
}

function printReport(r) {
  console.log(`\n=== EviTaint evaluation (${r.apps.join(', ')}) ===\n`);
  const head = ['ablation', 'P', 'R', 'F1', 'F1 95% CI', 'trace', 'faith', 'ECE'];
  const rows = Object.entries(r.ablations).map(([name, a]) => [
    name, a.detection.micro.precision, a.detection.micro.recall, a.detection.micro.f1,
    a.f1CI ? `[${a.f1CI.lo},${a.f1CI.hi}]` : '-', a.traceQuality ?? '-', a.meanFaithfulness ?? '-', a.calibration.ece,
  ]);
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((row) => String(row[i]).length)));
  const fmt = (row) => row.map((c, i) => String(c).padEnd(widths[i])).join('  ');
  console.log(fmt(head)); console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const row of rows) console.log(fmt(row));
  const full = r.ablations.full;
  console.log('\nPer-category (full):');
  for (const [c, m] of Object.entries(full.detection.byCategory)) console.log(`  ${c.padEnd(9)} P=${m.precision} R=${m.recall} F1=${m.f1} (tp=${m.tp} fp=${m.fp} fn=${m.fn})`);
  if (full.confirmedRate != null) console.log(`\nConfirmed rate: ${full.confirmedRate}  Causally-supported rate: ${full.causallySupportedRate}`);
}

run().catch((e) => { console.error(e); process.exit(1); });
