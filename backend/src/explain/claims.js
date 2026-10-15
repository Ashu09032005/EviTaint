/**
 * Evidence-Carrying Explanations (N1).
 *
 * An explanation is a list of atomic claims. Each claim is bound to a concrete,
 * machine-checkable artifact (an AST offset, a trace step, a confirmation
 * record, a counterfactual result). The Claim Checker verifies every claim
 * against the actual analysis artifacts. Only verified claims may appear in the
 * final explanation; unverified claims are dropped or explicitly marked
 * "unsupported". Natural-language prose (template or LLM) only ever verbalizes
 * claims that passed the checker, so it cannot assert anything the evidence
 * does not support.
 */

/** Build the claim set for a finding from its trace + optional dynamic evidence. */
export function buildClaims(finding, { confirmation, counterfactual } = {}) {
  const claims = [];
  const sink = finding.trace.find((s) => s.kind === 'sink');
  const push = (c) => claims.push({ id: `${finding.id}-c${claims.length + 1}`, ...c });

  // C1: a source of untrusted input exists at a specific location.
  push({
    kind: 'source-exists',
    text: `Untrusted input enters at ${finding.source.file}:${finding.source.line} via ${finding.source.label}.`,
    evidence: { type: 'ast-node', file: finding.source.file, line: finding.source.line, offsets: [finding.trace[0]?.start, finding.trace[0]?.end], code: finding.source.code },
  });

  // C2: a dangerous sink exists at a specific location.
  push({
    kind: 'sink-exists',
    text: `A ${finding.categoryName} sink (${finding.sink}) is called at ${sink.file}:${sink.line}.`,
    evidence: { type: 'ast-node', file: sink.file, line: sink.line, offsets: [sink.start, sink.end], code: sink.code },
  });

  // C3: an ordered data-flow path connects source to sink (each hop an artifact).
  push({
    kind: 'flow-path',
    text: `The input propagates to the sink through ${finding.trace.length} step(s)${finding.interprocedural ? ', crossing at least one function call' : ''}${finding.crossFile ? ' and at least one file boundary' : ''}.`,
    evidence: { type: 'trace', steps: finding.trace.map((s) => ({ kind: s.kind, file: s.file, line: s.line, offsets: [s.start, s.end], detail: s.detail })) },
  });

  // C4: no sanitizer for this category is present on the path.
  push({
    kind: 'no-sanitizer',
    text: finding.sanitizedFor.length
      ? `The path applies sanitizers for [${finding.sanitizedFor.join(', ')}], none of which neutralize ${finding.category}.`
      : `No sanitizer for ${finding.category} is applied anywhere on the path.`,
    evidence: { type: 'trace-absence', sanitizerSteps: finding.trace.filter((s) => s.kind === 'sanitizer').map((s) => s.detail), category: finding.category },
  });

  // C5: assumptions (unresolved calls) made while deriving the path.
  if (finding.assumptions.length) {
    push({
      kind: 'assumption',
      text: `The path relies on ${finding.assumptions.length} unverified assumption(s): ${finding.assumptions.join('; ')}.`,
      evidence: { type: 'assumptions', items: finding.assumptions },
      soft: true,
    });
  }

  // C6: dynamic reachability (only if a confirmation run exists).
  if (confirmation && confirmation.status !== 'not-applicable') {
    push({
      kind: 'dynamic-reachability',
      text: {
        confirmed: 'A benign marker injected as the request input reached this sink unmodified at runtime.',
        'sanitized-at-runtime': 'At runtime the input reached the sink only in neutralized form.',
        'not-reached': 'At runtime the input did not reach this sink on the default execution path.',
        inconclusive: 'Dynamic confirmation was inconclusive (handler did not settle or branch not taken).',
        error: 'Dynamic confirmation could not run.',
      }[confirmation.status] || `Dynamic confirmation: ${confirmation.status}.`,
      evidence: { type: 'confirmation', status: confirmation.status, record: confirmation.evidence || confirmation.reason },
    });
  }

  // C7: counterfactual causal support.
  if (counterfactual && counterfactual.status !== 'skipped') {
    push({
      kind: 'counterfactual',
      text: counterfactual.causallySupported
        ? 'Sanitizing or removing the sink argument eliminates the finding, confirming the source→sink relation causes the alert.'
        : 'Counterfactual edits did not cleanly remove the finding; causal support is partial.',
      evidence: { type: 'counterfactual', causallySupported: counterfactual.causallySupported, sanitizingPatch: counterfactual.sanitizingPatch, flowBreakingEdit: counterfactual.flowBreakingEdit },
    });
  }

  return claims;
}

/** Secret findings get a small, self-contained claim set. */
export function buildSecretClaims(finding) {
  return [
    { id: `${finding.id}-c1`, kind: 'secret-literal', text: `A hardcoded ${finding.secretEvidence?.ruleName || 'secret'} appears at ${finding.file}:${finding.line}.`, evidence: { type: 'secret-location', file: finding.file, line: finding.line, offsets: [finding.trace[0].start, finding.trace[0].end] } },
    { id: `${finding.id}-c2`, kind: 'secret-evidence', text: `Detector rule: ${finding.secretEvidence?.rule} (entropy ${finding.secretEvidence?.entropy} bits/char, length ${finding.secretEvidence?.length}).`, evidence: { type: 'detector', ...finding.secretEvidence } },
  ];
}
