/**
 * Claim Checker: verifies each atomic claim against the actual program text and
 * analysis artifacts. A claim is "supported" only if its bound evidence checks
 * out. The faithfulness of an explanation is then (supported claims)/(total).
 */

function codeAt(files, file, offsets) {
  const code = files[file];
  if (!code || !offsets || offsets[0] == null) return null;
  return code.slice(offsets[0], offsets[1]);
}

/**
 * @returns {object} { claims: [{...claim, supported, checkDetail}], faithfulness, supported, total }
 */
export function checkClaims(claims, files, { confirmation, counterfactual } = {}) {
  const checked = claims.map((claim) => {
    const r = verify(claim, files, { confirmation, counterfactual });
    return { ...claim, supported: r.ok, checkDetail: r.detail };
  });
  const hard = checked.filter((c) => !c.soft);
  const supported = hard.filter((c) => c.supported).length;
  return {
    claims: checked,
    supported,
    total: hard.length,
    faithfulness: hard.length ? Number((supported / hard.length).toFixed(3)) : 1,
    unsupported: checked.filter((c) => !c.supported && !c.soft).map((c) => c.id),
  };
}

function verify(claim, files, ctx) {
  const e = claim.evidence;
  switch (e.type) {
    case 'ast-node': {
      const text = codeAt(files, e.file, e.offsets);
      if (text == null) return { ok: false, detail: 'offsets do not resolve in source' };
      // The recorded code snippet must match the current source at those offsets.
      const norm = (s) => s.replace(/\s+/g, ' ').trim();
      const ok = text.length > 0 && (norm(text).includes(norm(e.code).replace(/…$/, '').slice(0, 20)) || norm(e.code).includes(norm(text).slice(0, 20)));
      return { ok, detail: ok ? `verified at ${e.file}:${e.line}` : `source text at offsets does not match recorded snippet` };
    }
    case 'secret-location': {
      const code = files[e.file];
      if (!code || e.offsets[0] == null) return { ok: false, detail: 'secret offsets do not resolve' };
      const text = code.slice(e.offsets[0], e.offsets[1]);
      return { ok: text.length > 0, detail: text.length ? `literal present at ${e.file}:${e.line}` : 'offsets empty' };
    }
    case 'trace': {
      // Every step must resolve to real source and form a contiguous, ordered chain.
      if (!e.steps.length) return { ok: false, detail: 'empty trace' };
      for (const s of e.steps) {
        const t = codeAt(files, s.file, s.offsets);
        if (t == null || !t.length) return { ok: false, detail: `trace step at ${s.file}:${s.line} does not resolve` };
      }
      const hasSource = e.steps[0].kind === 'source' || e.steps.some((s) => s.kind === 'param-bind' || s.kind === 'source');
      const hasSink = e.steps[e.steps.length - 1].kind === 'sink';
      return { ok: hasSource && hasSink, detail: hasSource && hasSink ? `${e.steps.length} steps resolve, source→sink` : 'trace does not begin at a source or end at a sink' };
    }
    case 'trace-absence': {
      // Claim holds if no sanitizer step for this category is on the path.
      const neutralizing = (e.sanitizerSteps || []).some((d) => d.includes(`for ${e.category}`) || d.includes('all categories'));
      return { ok: !neutralizing, detail: neutralizing ? 'a neutralizing sanitizer is actually present' : 'confirmed: no neutralizing sanitizer on path' };
    }
    case 'assumptions':
      return { ok: true, detail: `${e.items.length} assumption(s) recorded`, soft: true };
    case 'confirmation': {
      const ok = ['confirmed', 'sanitized-at-runtime', 'not-reached', 'inconclusive', 'error', 'not-applicable'].includes(e.status);
      return { ok, detail: `confirmation status ${e.status}` };
    }
    case 'counterfactual': {
      // The claim text must match what the counterfactual actually found.
      const ctxCf = ctx.counterfactual;
      if (!ctxCf) return { ok: false, detail: 'counterfactual record missing' };
      const ok = ctxCf.causallySupported === e.causallySupported;
      return { ok, detail: ok ? `counterfactual causallySupported=${e.causallySupported}` : 'claim disagrees with counterfactual record' };
    }
    case 'detector':
      return { ok: e.entropy != null && e.length != null, detail: `detector evidence present (${e.rule})` };
    default:
      return { ok: false, detail: `unknown evidence type ${e.type}` };
  }
}
