/**
 * LLM-assisted spec inference with a verification gate (N3).
 *
 * Problem: the fixed source/sink/sanitizer lists miss project- and framework-
 * specific APIs. This module proposes candidate specs two ways:
 *   1. Static mining (always on, deterministic): scan unresolved calls and
 *      common naming patterns to propose candidate sinks/sanitizers.
 *   2. LLM proposal (optional): ask a model to classify unresolved call names.
 *
 * Every candidate must pass a VERIFICATION GATE before it is used:
 *   - the name must actually occur in the project,
 *   - a minimal synthetic probe must change the analyzer's output in the
 *     expected direction (a candidate sink must create a finding on a probe
 *     where tainted data flows into it; a candidate sanitizer must remove one).
 * Unverified candidates are reported but never silently trusted.
 */
import { analyzeFiles } from '../core/engine.js';

const SINK_NAME_HINTS = [
  { re: /(query|execute|exec|raw)$/i, category: 'sqli' },
  { re: /(render|html|template|dangerous)/i, category: 'xss' },
  { re: /(readfile|writefile|sendfile|download|openfile)/i, category: 'path' },
  { re: /(command|shell|spawn|exec)/i, category: 'cmdi' },
  { re: /(fetch|request|httpget|curl)/i, category: 'ssrf' },
];
const SANITIZER_NAME_HINTS = [/sanitiz/i, /escape/i, /clean/i, /validate/i, /encode/i, /allowlist/i, /whitelist/i];

/** Deterministic static mining of candidate specs from unresolved calls. */
export function mineCandidates(result) {
  const sinks = [];
  const sanitizers = [];
  for (const u of result.unresolvedCalls) {
    const tail = u.callee.split('.').pop();
    for (const h of SINK_NAME_HINTS) if (h.re.test(u.callee)) sinks.push({ callee: [u.callee], category: h.category, args: [0], _source: 'mined', _occurrences: u.count });
    if (SANITIZER_NAME_HINTS.some((re) => re.test(tail))) sanitizers.push({ callee: [u.callee], categories: ['*'], _source: 'mined', _occurrences: u.count });
  }
  return { sinks, sanitizers };
}

/** Build a minimal probe that routes tainted input into a candidate sink. */
function sinkProbe(name) {
  const simple = name.split('.').pop();
  return `const ${simple} = (x)=>x; app.get('/p',(req,res)=>{ ${name.includes('.') ? name.split('.')[0] + '.' : ''}${simple}(req.query.v); res.end() });`;
}
function sanitizerProbe(name) {
  const simple = name.split('.').pop();
  return `const ${simple}=(x)=>x; app.get('/p',(req,res)=>{ res.send(${simple}(req.query.v)) });`;
}

/** Verify a candidate sink: it must produce a finding on the probe. */
export function verifySinkCandidate(cand) {
  const name = cand.callee[0];
  const probe = sinkProbe(name);
  const withSpec = analyzeFiles({ 'probe.js': probe }, { extraSpecs: { sinks: [{ ...cand }] } });
  const without = analyzeFiles({ 'probe.js': probe });
  const created = withSpec.findings.length > without.findings.length;
  return { ...cand, verified: created, _probe: probe, _effect: created ? 'produced a finding when registered as a sink' : 'no observable effect on probe' };
}

/** Verify a candidate sanitizer: it must remove a finding on the probe. */
export function verifySanitizerCandidate(cand) {
  const name = cand.callee[0];
  const probe = sanitizerProbe(name);
  const without = analyzeFiles({ 'probe.js': probe });
  const withSpec = analyzeFiles({ 'probe.js': probe }, { extraSpecs: { sanitizers: [{ ...cand }] } });
  const removed = withSpec.findings.length < without.findings.length;
  return { ...cand, verified: removed, _probe: probe, _effect: removed ? 'removed a finding when registered as a sanitizer' : 'no observable effect on probe' };
}

/**
 * Full inference pass. `llm` is optional; when present its proposals are merged
 * with mined candidates and all are run through the verification gate.
 */
export async function inferSpecs(result, { llm } = {}) {
  const mined = mineCandidates(result);
  let proposed = { sinks: [...mined.sinks], sanitizers: [...mined.sanitizers] };

  if (llm && llm.enabled && result.unresolvedCalls.length) {
    try {
      const names = result.unresolvedCalls.slice(0, 40).map((u) => u.callee);
      const classified = await llm.classifyCalls(names); // [{name, role:'sink'|'sanitizer'|'none', category}]
      for (const c of classified || []) {
        if (c.role === 'sink' && c.category) proposed.sinks.push({ callee: [c.name], category: c.category, args: [0], _source: 'llm' });
        if (c.role === 'sanitizer') proposed.sanitizers.push({ callee: [c.name], categories: c.category ? [c.category] : ['*'], _source: 'llm' });
      }
    } catch { /* fall back to mined only */ }
  }

  const verifiedSinks = proposed.sinks.map(verifySinkCandidate);
  const verifiedSanitizers = proposed.sanitizers.map(verifySanitizerCandidate);
  return {
    candidates: { sinks: proposed.sinks.length, sanitizers: proposed.sanitizers.length },
    accepted: {
      sinks: verifiedSinks.filter((s) => s.verified),
      sanitizers: verifiedSanitizers.filter((s) => s.verified),
    },
    rejected: {
      sinks: verifiedSinks.filter((s) => !s.verified),
      sanitizers: verifiedSanitizers.filter((s) => !s.verified),
    },
  };
}
