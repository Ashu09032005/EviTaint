/**
 * Calibrated confidence (N5).
 *
 * Confidence is NOT a fixed label. It is a score in [0,1] computed from
 * evidence features (trace length, interprocedural hops, assumptions, dynamic
 * confirmation, counterfactual support), then mapped through a monotonic
 * calibration curve fitted on labeled data (isotonic-style, stored as a step
 * function). Without a fitted curve the raw score is returned and flagged
 * uncalibrated. Expected Calibration Error (ECE) and Brier score are provided
 * for evaluation.
 */

/** Feature vector -> raw confidence via a transparent linear-logistic model. */
export function rawConfidence(finding, { confirmation, counterfactual } = {}) {
  let z = 0.2;
  z += finding.interprocedural ? -0.1 : 0.15; // direct flows are easier to get right
  z += finding.crossFile ? -0.1 : 0;
  z -= 0.25 * (finding.assumptions?.length || 0); // unresolved calls reduce certainty
  z += Math.max(-0.2, -0.03 * (finding.trace.length - 2));
  if (confirmation?.status === 'confirmed') z += 0.9;
  else if (confirmation?.status === 'sanitized-at-runtime') z -= 1.2;
  else if (confirmation?.status === 'not-reached') z -= 0.6;
  if (counterfactual?.causallySupported) z += 0.5;
  else if (counterfactual && counterfactual.causallySupported === false) z -= 0.3;
  const p = 1 / (1 + Math.exp(-2.0 * z));
  return Number(p.toFixed(4));
}

/** Fit an isotonic (pool-adjacent-violators) calibration curve. */
export function fitIsotonic(pairs) {
  // pairs: [{score, label(0/1)}]
  const sorted = [...pairs].sort((a, b) => a.score - b.score);
  const blocks = sorted.map((p) => ({ x: p.score, y: p.label, w: 1 }));
  let i = 0;
  while (i < blocks.length - 1) {
    if (blocks[i].y > blocks[i + 1].y) {
      const w = blocks[i].w + blocks[i + 1].w;
      const y = (blocks[i].y * blocks[i].w + blocks[i + 1].y * blocks[i + 1].w) / w;
      blocks.splice(i, 2, { x: blocks[i + 1].x, y, w });
      if (i > 0) i--;
    } else i++;
  }
  return { type: 'isotonic', points: blocks.map((b) => ({ x: b.x, y: Number(b.y.toFixed(4)) })) };
}

export function applyCalibration(score, curve) {
  if (!curve || !curve.points?.length) return { calibrated: score, uncalibrated: true };
  const pts = curve.points;
  if (score <= pts[0].x) return { calibrated: pts[0].y, uncalibrated: false };
  if (score >= pts[pts.length - 1].x) return { calibrated: pts[pts.length - 1].y, uncalibrated: false };
  for (let i = 0; i < pts.length - 1; i++) {
    if (score >= pts[i].x && score <= pts[i + 1].x) {
      const t = (score - pts[i].x) / (pts[i + 1].x - pts[i].x || 1);
      return { calibrated: Number((pts[i].y + t * (pts[i + 1].y - pts[i].y)).toFixed(4)), uncalibrated: false };
    }
  }
  return { calibrated: score, uncalibrated: false };
}

export function severityFromConfidence(baseSeverity, p) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const names = ['info', 'low', 'medium', 'high', 'critical'];
  let r = rank[baseSeverity] ?? 2;
  if (p < 0.25) r = Math.max(0, r - 2);
  else if (p < 0.5) r = Math.max(0, r - 1);
  return names[r];
}

/** Expected Calibration Error over equal-width bins. */
export function expectedCalibrationError(pairs, bins = 10) {
  const b = Array.from({ length: bins }, () => ({ n: 0, conf: 0, acc: 0 }));
  for (const { score, label } of pairs) {
    const idx = Math.min(bins - 1, Math.floor(score * bins));
    b[idx].n++; b[idx].conf += score; b[idx].acc += label;
  }
  const n = pairs.length || 1;
  let ece = 0;
  const detail = b.filter((x) => x.n).map((x) => ({ n: x.n, meanConf: Number((x.conf / x.n).toFixed(3)), accuracy: Number((x.acc / x.n).toFixed(3)) }));
  for (const x of b) if (x.n) ece += (x.n / n) * Math.abs(x.acc / x.n - x.conf / x.n);
  return { ece: Number(ece.toFixed(4)), bins: detail };
}

export function brierScore(pairs) {
  if (!pairs.length) return 0;
  return Number((pairs.reduce((s, p) => s + (p.score - p.label) ** 2, 0) / pairs.length).toFixed(4));
}
