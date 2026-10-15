#!/usr/bin/env node
/**
 * Fit a calibration curve from labeled benchmark findings and save it so the
 * pipeline can report calibrated confidences. Demonstrates the N5 workflow:
 * raw score -> isotonic curve -> calibrated probability with ECE/Brier before
 * and after.
 *
 * Usage: node scripts/calibrate.js [--out calibration.json]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readProject } from '../src/core/project.js';
import { runPipeline } from '../src/pipeline.js';
import { rawConfidence, fitIsotonic, applyCalibration, expectedCalibrationError, brierScore } from '../src/explain/calibration.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BENCH = path.join(__dirname, '..', '..', 'benchmark');
const key = (f, l) => `${f}:${l}`;

async function run() {
  const outIdx = process.argv.indexOf('--out');
  const outFile = outIdx >= 0 ? process.argv[outIdx + 1] : path.join(BENCH, 'calibration.json');
  const labelsDir = path.join(BENCH, 'labels');
  const pairs = [];
  for (const lf of fs.readdirSync(labelsDir).filter((f) => f.endsWith('.json'))) {
    const label = JSON.parse(fs.readFileSync(path.join(labelsDir, lf), 'utf8'));
    const dir = path.join(BENCH, 'apps', label.app);
    if (!fs.existsSync(dir)) continue;
    const { files } = readProject(dir);
    const pos = new Map(label.positives.map((p) => [key(p.file, p.line), p.category])); // eslint-disable-line no-await-in-loop
    const report = await runPipeline(files, { confirm: true, counterfactual: true }); // eslint-disable-line no-await-in-loop
    for (const f of report.findings) {
      const raw = rawConfidence(f, { confirmation: report.confirmations[f.id], counterfactual: report.counterfactuals[f.id] });
      const isTP = pos.get(key(f.file, f.line)) === f.category ? 1 : 0;
      pairs.push({ score: raw, label: isTP });
    }
  }
  if (pairs.length < 4) { console.error('not enough findings to calibrate'); process.exit(1); }
  const curve = fitIsotonic(pairs);
  const before = { ...expectedCalibrationError(pairs), brier: brierScore(pairs) };
  const after = (() => { const cp = pairs.map((p) => ({ score: applyCalibration(p.score, curve).calibrated, label: p.label })); return { ...expectedCalibrationError(cp), brier: brierScore(cp) }; })();
  fs.writeFileSync(outFile, JSON.stringify({ curve, n: pairs.length, before, after }, null, 2));
  console.log(`Fitted isotonic curve on ${pairs.length} findings.`);
  console.log(`ECE   : ${before.ece} -> ${after.ece}`);
  console.log(`Brier : ${before.brier} -> ${after.brier}`);
  console.log(`curve -> ${outFile}`);
  console.log('Pass this file to runPipeline via options.calibrationCurve to report calibrated confidences.');
}
run().catch((e) => { console.error(e); process.exit(1); });
