#!/usr/bin/env node
/**
 * EviTaint CLI:  evitaint <projectDir> [--confirm] [--counterfactual]
 *                [--infer-specs] [--json out.json] [--sarif out.sarif]
 */
import fs from 'node:fs';
import path from 'node:path';
import { readProject } from './core/project.js';
import { runPipeline } from './pipeline.js';
import { createLLM } from './llm/client.js';
import { toSARIF } from './report/sarif.js';

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) { const k = a.slice(2); if (['json', 'sarif'].includes(k)) args.flags[k] = argv[++i]; else args.flags[k] = true; }
    else args._.push(a);
  }
  return args;
}

async function main() {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const dir = _[0];
  if (!dir) { console.error('usage: evitaint <projectDir> [--confirm] [--counterfactual] [--infer-specs] [--json out] [--sarif out]'); process.exit(2); }
  const root = path.resolve(dir);
  if (!fs.existsSync(root)) { console.error(`no such directory: ${root}`); process.exit(2); }

  const { files, skipped } = readProject(root);
  const llm = createLLM();
  const report = await runPipeline(files, {
    confirm: Boolean(flags.confirm),
    counterfactual: Boolean(flags.counterfactual),
    dynamicCounterfactual: Boolean(flags.confirm && flags.counterfactual),
    inferSpecs: Boolean(flags['infer-specs']),
    llm: llm.enabled ? llm : null,
  });
  report.meta.skippedFiles = skipped;

  if (flags.json) fs.writeFileSync(flags.json, JSON.stringify(report, null, 2));
  if (flags.sarif) fs.writeFileSync(flags.sarif, JSON.stringify(toSARIF(report), null, 2));
  printSummary(report, llm);
  if (!flags.json && !flags.sarif) printFindings(report);
}

function printSummary(r, llm) {
  const s = r.summary;
  console.log(`\nEviTaint ${r.meta.version}  —  ${s.total} finding(s)`);
  console.log(`Coverage: ${s.coverage.parsed}/${s.coverage.discovered} files parsed (${s.coverage.partial} partial, ${s.coverage.failed} failed)`);
  console.log(`Severity: ${Object.entries(s.bySeverity).map(([k, v]) => `${k}=${v}`).join(' ') || '-'}`);
  if (r.meta.options.confirm) console.log(`Dynamically confirmed: ${s.confirmed}/${s.total}`);
  if (r.meta.options.counterfactual) console.log(`Causally supported:   ${s.causallySupported}/${s.total}`);
  console.log(`Mean explanation faithfulness: ${s.meanFaithfulness ?? 'n/a'}`);
  console.log(`LLM: ${llm.enabled ? r.meta.options.llm ? llm.model : 'available' : 'disabled (deterministic)'}`);
  if (r.specInference) console.log(`Spec inference: accepted ${r.specInference.accepted.sinks.length} sink(s), ${r.specInference.accepted.sanitizers.length} sanitizer(s); rejected ${r.specInference.rejected.sinks.length + r.specInference.rejected.sanitizers.length}`);
}

function printFindings(r) {
  for (const f of r.findings) {
    const c = f.confidence;
    console.log(`\n[${f.severity.toUpperCase()}] ${f.categoryName} (${f.cwe})  conf=${c.calibrated}${c.uncalibrated ? '~' : ''}  faith=${f.faithfulness}`);
    console.log(`  ${f.file}:${f.line}  sink=${f.sink}`);
    if (f.route) console.log(`  route: ${f.route.method.toUpperCase()} ${f.route.path}`);
    if (f.confirmation) console.log(`  dynamic: ${f.confirmation}`);
    if (f.counterfactual != null) console.log(`  counterfactual: ${f.counterfactual ? 'causally supported' : 'not confirmed'}`);
    console.log(`  ${r.explanations[f.id].prose}`);
  }
  for (const g of [...r.coverage.filesFailed, ...r.coverage.filesPartiallyParsed]) {
    console.log(`\n[COVERAGE GAP] ${g.file}: ${g.errors.map((e) => e.message).join(', ')}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
