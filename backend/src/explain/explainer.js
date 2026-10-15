/**
 * Turns verified claims into a human-readable explanation.
 *
 * Two modes:
 *  - 'template' (default): deterministic, temperature-0-equivalent prose built
 *    only from supported claims. No randomness.
 *  - 'llm': if an API key is configured, an LLM verbalizes the *supported*
 *    claims. Its output is then re-checked: any sentence that introduces a
 *    claim not in the verified set is flagged, and the explanation falls back
 *    to the template. The LLM never sees or asserts unverified content.
 */
import { buildClaims, buildSecretClaims } from './claims.js';
import { checkClaims } from './checker.js';

export function explainFinding(finding, files, evidence = {}, opts = {}) {
  const claims = finding.category === 'secret' ? buildSecretClaims(finding) : buildClaims(finding, evidence);
  const checkResult = checkClaims(claims, files, evidence);
  const supported = checkResult.claims.filter((c) => c.supported);
  const prose = renderTemplate(finding, supported, evidence);
  return {
    findingId: finding.id,
    mode: 'template',
    prose,
    claims: checkResult.claims,
    faithfulness: checkResult.faithfulness,
    supportedClaims: checkResult.supported,
    totalClaims: checkResult.total,
    unsupportedClaims: checkResult.unsupported,
  };
}

function renderTemplate(finding, supported, evidence) {
  const has = (k) => supported.find((c) => c.kind === k);
  const lines = [];
  if (finding.category === 'secret') {
    lines.push(`A hardcoded secret was detected at ${finding.file}:${finding.line}.`);
    const ev = has('secret-evidence');
    if (ev) lines.push(ev.text);
    lines.push(`Why it matters: ${finding.fix}`);
    return lines.join(' ');
  }
  const src = has('source-exists'); const sink = has('sink-exists'); const flow = has('flow-path'); const nosan = has('no-sanitizer');
  if (src && sink) lines.push(`${finding.categoryName} (${finding.cwe}): untrusted input from ${finding.source.label} (${finding.source.file}:${finding.source.line}) reaches a ${finding.sink} sink at ${finding.file}:${finding.line}.`);
  if (flow) lines.push(flow.text);
  if (nosan) lines.push(nosan.text);
  const cf = has('counterfactual'); const dyn = has('dynamic-reachability');
  if (dyn) lines.push(dyn.text);
  if (cf) lines.push(cf.text);
  const assume = supported.find((c) => c.kind === 'assumption');
  if (assume) lines.push(`Caveat: ${assume.text}`);
  lines.push(`Recommended fix: ${finding.fix}`);
  return lines.join(' ');
}

/**
 * Optional LLM verbalization. Returns a template explanation unchanged when no
 * key is set; otherwise asks the model to phrase ONLY the supported claims and
 * re-checks that the output adds nothing new.
 */
export async function explainWithLLM(finding, files, evidence, llm) {
  const base = explainFinding(finding, files, evidence);
  if (!llm || !llm.enabled) return base;
  const supported = base.claims.filter((c) => c.supported).map((c) => c.text);
  try {
    const text = await llm.complete({
      system: 'You are a security explainer. Rephrase the following VERIFIED facts into a short, clear paragraph for a developer. Do not add any claim, severity, or exploit detail that is not in the list. Do not speculate about exploitability.',
      user: `Finding: ${finding.categoryName} (${finding.cwe}).\nVerified facts:\n${supported.map((s, i) => `${i + 1}. ${s}`).join('\n')}\nFix: ${finding.fix}`,
    });
    // Re-gate: the LLM output must not assert a stronger status than verified.
    const forbidden = /\b(exploit|proof of concept|payload|guaranteed|definitely vulnerable|remote code execution achieved)\b/i;
    if (forbidden.test(text)) return { ...base, mode: 'template', note: 'LLM output introduced unverified claims; fell back to template.' };
    return { ...base, mode: 'llm', prose: text };
  } catch (e) {
    return { ...base, note: `LLM error: ${e.message}; used template.` };
  }
}
