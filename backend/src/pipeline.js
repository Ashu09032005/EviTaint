/**
 * EviTaint pipeline orchestrator.
 *
 * Stages (each optional via options):
 *   1. parse + coverage          (always)
 *   2. static taint analysis     (always)
 *   3. secret detection          (always)
 *   4. spec inference + gate     (opt: inferSpecs) -> re-run static with accepted specs
 *   5. dynamic confirmation      (opt: confirm)
 *   6. counterfactual verify     (opt: counterfactual)
 *   7. evidence-carrying explain + claim check   (always)
 *   8. calibrated confidence     (always; curve optional)
 */
import { buildProject } from './core/project.js';
import { TaintEngine } from './core/engine.js';
import { detectSecrets } from './core/secrets.js';
import { confirmFinding } from './confirm/harness.js';
import { counterfactual } from './confirm/counterfactual.js';
import { explainFinding, explainWithLLM } from './explain/explainer.js';
import { rawConfidence, applyCalibration, severityFromConfidence } from './explain/calibration.js';
import { inferSpecs } from './specs/inference.js';

export async function runPipeline(files, options = {}) {
  const opts = {
    interprocedural: true, sanitizers: true, killOnReassign: true, templateLiterals: true,
    inferSpecs: false, confirm: false, counterfactual: false, dynamicCounterfactual: false,
    llm: null, calibrationCurve: null, ...options,
  };
  const startedAt = new Date().toISOString();

  // 1-3 static
  let project = buildProject(files);
  let engine = new TaintEngine(project, opts);
  let result = engine.run();
  let specInference = null;

  // 4 spec inference + gate, then re-run with accepted specs
  if (opts.inferSpecs) {
    specInference = await inferSpecs(result, { llm: opts.llm });
    const extraSpecs = { sinks: specInference.accepted.sinks, sanitizers: specInference.accepted.sanitizers };
    if (extraSpecs.sinks.length || extraSpecs.sanitizers.length) {
      project = buildProject(files);
      engine = new TaintEngine(project, { ...opts, extraSpecs });
      result = engine.run();
    }
  }

  const secrets = detectSecrets(project);
  let findings = [...result.findings, ...secrets];

  // 5-8 per-finding evidence
  const confirmations = {}; const counterfactuals = {}; const explanations = {};
  for (const f of findings) {
    let conf = null; let cf = null;
    if (opts.confirm) { try { conf = await confirmFinding(f, files); } catch (e) { conf = { status: 'error', reason: e.message }; } confirmations[f.id] = conf; } // eslint-disable-line no-await-in-loop
    if (opts.counterfactual) { try { cf = await counterfactual(f, files, { dynamic: opts.dynamicCounterfactual }); } catch (e) { cf = { status: 'error', reason: e.message }; } counterfactuals[f.id] = cf; } // eslint-disable-line no-await-in-loop
    const evidence = { confirmation: conf, counterfactual: cf };
    const explanation = opts.llm?.enabled // eslint-disable-next-line no-await-in-loop
      ? await explainWithLLM(f, files, evidence, opts.llm)
      : explainFinding(f, files, evidence);
    explanations[f.id] = explanation;

    const raw = rawConfidence(f, evidence);
    const cal = applyCalibration(raw, opts.calibrationCurve);
    f.confidence = { raw, calibrated: cal.calibrated, uncalibrated: cal.uncalibrated };
    f.severity = severityFromConfidence(f.severity, cal.calibrated);
    f.faithfulness = explanation.faithfulness;
    f.confirmation = conf ? conf.status : null;
    f.counterfactual = cf ? (cf.causallySupported ?? null) : null;
  }

  findings.sort((a, b) => (b.confidence.calibrated - a.confidence.calibrated) || a.file.localeCompare(b.file) || a.line - b.line);

  return {
    meta: {
      tool: 'EviTaint', version: '1.0.0', startedAt, finishedAt: new Date().toISOString(),
      options: { interprocedural: opts.interprocedural, sanitizers: opts.sanitizers, killOnReassign: opts.killOnReassign, templateLiterals: opts.templateLiterals, inferSpecs: opts.inferSpecs, confirm: opts.confirm, counterfactual: opts.counterfactual, llm: Boolean(opts.llm?.enabled) },
      stats: result.stats,
    },
    coverage: project.coverage,
    summary: summarize(findings, project.coverage),
    findings,
    explanations,
    confirmations,
    counterfactuals,
    specInference,
    suppressed: result.suppressed,
    unresolvedCalls: result.unresolvedCalls.slice(0, 25),
    routes: result.routes,
  };
}

function summarize(findings, coverage) {
  const byCat = {}; const bySev = {};
  for (const f of findings) { byCat[f.category] = (byCat[f.category] || 0) + 1; bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
  const faiths = findings.map((f) => f.faithfulness).filter((x) => x != null);
  return {
    total: findings.length,
    byCategory: byCat,
    bySeverity: bySev,
    confirmed: findings.filter((f) => f.confirmation === 'confirmed').length,
    causallySupported: findings.filter((f) => f.counterfactual === true).length,
    meanFaithfulness: faiths.length ? Number((faiths.reduce((a, b) => a + b, 0) / faiths.length).toFixed(3)) : null,
    coverage: { discovered: coverage.filesDiscovered, parsed: coverage.filesParsed, partial: coverage.filesPartiallyParsed.length, failed: coverage.filesFailed.length },
  };
}
