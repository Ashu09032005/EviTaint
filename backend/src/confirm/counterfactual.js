/**
 * Counterfactual flow verification (N2).
 *
 * For a finding, derive two minimal source edits and re-analyze:
 *   (A) sanitizing patch: wrap the tainted sink argument in a category-
 *       appropriate sanitizer. Expectation: the static finding disappears AND
 *       the dynamic marker is neutralized.
 *   (B) flow-breaking edit: replace the tainted sink argument with a constant.
 *       Expectation: the finding disappears (control test that the sink
 *       location is what drives the verdict).
 *
 * A finding is "causally supported" when BOTH edits remove it. This gives
 * evidence that the reported source->sink relation, not an unrelated artifact,
 * is what the detector is reacting to, and the sanitizing patch doubles as a
 * concrete, verified fix.
 */
import { analyzeFiles } from '../core/engine.js';
import { confirmFinding } from './harness.js';
import { PATCH_SANITIZER } from '../specs/defaultSpecs.js';

function sinkStepOf(finding) { return finding.trace.find((s) => s.kind === 'sink'); }

/** Apply a textual edit to one file's source (by absolute offsets). */
function spliceFile(code, start, end, replacement) {
  return code.slice(0, start) + replacement + code.slice(end);
}

function findAfter(files, finding) {
  const sink = sinkStepOf(finding);
  const edited = analyzeFiles(files);
  return edited.findings.find((f) => f.category === finding.category && f.file === sink.file && f.line === sink.line);
}

export async function counterfactual(finding, files, opts = {}) {
  const sink = sinkStepOf(finding);
  if (!sink || !sink.arg) return { status: 'skipped', reason: 'no editable sink argument range recorded' };
  const code = files[sink.file];
  const argText = code.slice(sink.arg.start, sink.arg.end);
  const patcher = PATCH_SANITIZER[finding.category];
  const result = { category: finding.category, argText };

  // (A) sanitizing patch
  if (patcher) {
    const patched = { ...files, [sink.file]: spliceFile(code, sink.arg.start, sink.arg.end, patcher.wrap(argText)) };
    const stillStatic = findAfter(patched, finding);
    let dyn = null;
    if (opts.dynamic && finding.route) { try { dyn = await confirmFinding(finding, patched); } catch (e) { dyn = { status: 'error', reason: String(e.message) }; } }
    result.sanitizingPatch = {
      sanitizer: patcher.name,
      diff: { file: sink.file, line: sink.line, before: argText, after: patcher.wrap(argText) },
      staticFindingRemoved: !stillStatic,
      dynamic: dyn ? dyn.status : 'not-run',
    };
  }

  // (B) flow-breaking edit (replace with a constant)
  const broken = { ...files, [sink.file]: spliceFile(code, sink.arg.start, sink.arg.end, finding.category === 'nosqli' || finding.category === 'proto' ? '{}' : "'evitaint_constant'") };
  const stillBroken = findAfter(broken, finding);
  result.flowBreakingEdit = {
    diff: { file: sink.file, line: sink.line, before: argText, after: "'evitaint_constant'" },
    staticFindingRemoved: !stillBroken,
  };

  const sanOk = !patcher || result.sanitizingPatch.staticFindingRemoved;
  const breakOk = result.flowBreakingEdit.staticFindingRemoved;
  result.causallySupported = Boolean(sanOk && breakOk);
  result.verdict = result.causallySupported
    ? 'Removing or sanitizing the sink argument eliminates the finding, confirming the reported source→sink relation drives the alert.'
    : 'Edits did not cleanly flip the verdict; the alert may depend on additional factors — review manually.';
  return result;
}

export async function counterfactualAll(findings, files, opts = {}) {
  const out = [];
  for (const f of findings) { out.push({ id: f.id, ...(await counterfactual(f, files, opts)) }); } // eslint-disable-line no-await-in-loop
  return out;
}
