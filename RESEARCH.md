# EviTaint — Research Agenda, Gap Mapping, and Results

This document ties the implementation to the research gaps it addresses, states
the experiments, reports the results produced by the bundled benchmark, and
lays out the validation agenda (including the human study) needed for a
submission-ready paper.

> Scope note. The bundled `benchmark/` is a *small, purpose-built* corpus for
> functional validation and ablation, mirroring the honesty of the source
> manuscript: these results establish that each mechanism works and isolates its
> contribution. They are **not** a benchmark score and do not support claims of
> cross-project precision/recall. The larger, leakage-controlled evaluation is
> described in §5.

---

## 1. Gap → module → experiment

| Gap (from prior prototype evaluation) | EviTaint module | Experiment |
|---|---|---|
| G1 Shallow analysis (no scope, interprocedural, sanitizers) | `core/engine.js` (binding-scoped, flow-sensitive, summary-based interprocedural, sanitizer barriers, kill-on-reassign, template literals) | Ablation: `full` vs `no-interprocedural`, `no-sanitizers`, `no-kill-on-reassign`, `no-template-literals`, `prototype-equivalent` |
| G2 Fixed, incomplete specs | `specs/inference.js` (mined + LLM candidates, **verification gate**) | Spec-inference acceptance/rejection on probes; `test/pipeline.test.js` |
| G3 Unfaithful explanations | `explain/claims.js`, `explain/checker.js` | Explanation faithfulness = supported/total claims; tamper test |
| G4 No confirmation (candidates only) | `confirm/harness.js` + `confirm/worker.js` (benign-marker reachability) | Confirmation rate; `confirmed` vs `sanitized-at-runtime` vs `not-reached` |
| G5 No counterfactual evidence | `confirm/counterfactual.js` | Counterfactual validity rate; patch removes finding |
| G6 Uncalibrated confidence, silent failures | `explain/calibration.js`; coverage in `core/project.js` | ECE/Brier before/after calibration; coverage-gap reporting |
| G7 No labeled evaluation | `benchmark/` + `scripts/evaluate.js` | Line-level P/R/F1 with bootstrap CIs, per category |

---

## 2. Results on the bundled benchmark (3 apps, 8 positives, 9 negatives)

Detection (micro, line-level unit), trace quality, explanation faithfulness,
and calibration error per ablation:

| Ablation | P | R | F1 | F1 95% CI | Trace | Faith | ECE |
|---|---|---|---|---|---|---|---|
| **full** | 1.00 | 1.00 | **1.00** | [1.00, 1.00] | 1.00 | 1.00 | 0.074 |
| no-interprocedural | 1.00 | 0.875 | 0.933 | [0.77, 1.00] | 1.00 | 1.00 | — |
| no-sanitizers | 0.667 | 1.00 | 0.800 | [0.59, 0.96] | 1.00 | 1.00 | — |
| no-kill-on-reassign | 0.889 | 1.00 | 0.941 | [0.80, 1.00] | 1.00 | 1.00 | — |
| no-template-literals | 1.00 | 0.75 | 0.857 | [0.55, 1.00] | 1.00 | 1.00 | — |
| **prototype-equivalent** | 0.50 | 0.625 | **0.556** | [0.27, 0.76] | 1.00 | 1.00 | — |

Reading the ablations:
- **Interprocedural** analysis recovers the cross-file SQL-injection positive
  (recall 0.875 → 1.00).
- **Sanitizer modeling** removes 4 false positives on correctly-escaped /
  parameterized / guarded code (precision 0.667 → 1.00).
- **Kill-on-reassign** removes the "taint survives benign reassignment" false
  positive (precision 0.889 → 1.00).
- **Template-literal propagation** recovers 2 positives the original prototype
  missed (recall 0.75 → 1.00).
- The **prototype-equivalent** configuration (all four off) collapses to
  F1 0.556 — reproducing the failure modes documented in the source manuscript.

Dynamic evidence (full config): confirmed rate **0.875**, causally-supported
rate **0.875** (the hardcoded-secret finding is static-only, and one SQLi flow
is dynamically *inconclusive* because the demo omits the DB binding — reported
honestly rather than claimed).

Calibration (fitted isotonic curve, `scripts/calibrate.js`): ECE **0.074 → 0**,
Brier **0.014 → 0** on the benchmark findings. (On a held-out set these will not
reach 0; the point is the mechanism and the before/after reporting.)

Reproduce:
```bash
cd backend && npm run eval -- --confirm      # table + benchmark/evaluation_results.json
npm run calibrate                            # benchmark/calibration.json
```

---

## 3. Related work and the precise delta

| System | Target | Explanations | Confirmation | Gap EviTaint fills |
|---|---|---|---|---|
| CodeQL / Semgrep | multi-lang taint | trace, no claim-checking | no | explanations are not claim-verified; no counterfactual |
| IRIS (ICLR'25) | **Java**, LLM-inferred specs | no | no | spec inference, but Java and no faithfulness metric |
| SemTaint (2026) | **npm packages** | no | via CodeQL | packages, not web apps; no explanation faithfulness |
| LLMVD.js (2026) | **npm packages** | no | **exploit PoC** | packages; confirms by exploitation, no explanation check |
| LLMVulExp | C/C++ functions | human-rated only | no | explanations rated, never verified against the program |
| NodeMedic-FINE / Explode.js / Graph.js | Node **packages** | no | exploit/graph | packages; no evidence-carrying explanation |

**Delta.** No prior system, for JS/TS **web apps**, makes each statement in an
explanation checkable against program evidence (N1) and verifies the reported
flow with a re-analyzed counterfactual (N2). EviTaint confirms **reachability**
with a benign marker rather than generating exploits, which is the appropriate,
safe signal for the explanation-faithfulness question.

---

## 4. Metric definitions

- **Detection P/R/F1** — unit = `(file, line, category)` at the sink; matched
  against line-level ground truth with explicit negatives. Bootstrap 95% CIs
  over resampled finding outcomes.
- **Trace quality** — fraction of true-positive findings whose trace ends at the
  labeled sink line (extendable to full step-level trace F1 once traces are
  annotated).
- **Explanation faithfulness** — supported claims / total hard claims, where
  "supported" means the claim's bound evidence re-verifies against source.
- **Confirmation rate** — findings whose benign marker reached the sink intact.
- **Counterfactual validity** — findings where both the sanitizing patch and the
  flow-breaking edit remove the static finding.
- **Calibration** — ECE (10-bin) and Brier over findings labeled TP/FP.

---

## 5. Validation agenda (for a submission-ready paper)

What the bundled corpus does **not** yet support, and the plan to get there:

1. **EviTaint-Bench at scale.** Mine GitHub Security Advisories / OSV for JS/TS
   web-app CVEs with fix commits; build vulnerable/patched pairs from real
   Express/Next.js/NestJS projects; add OWASP Juice Shop, NodeGoat, DVNA; seed
   variants and safe look-alikes. Two annotators, line + trace labels, Cohen's κ,
   adjudication.
2. **Leakage control.** Project-disjoint and time-based splits (post-model-cutoff
   CVEs); renamed/minified variants to test memorization and robustness.
3. **Matched baselines.** CodeQL (default + extended), Semgrep taint mode,
   Graph.js/ODGen, and a pure-LLM agent, on the *same* projects, categories, and
   alert unit, with per-category P/R and runtime + cost, CIs throughout.
4. **Trace fidelity.** Step-level trace F1 against annotated paths; faithfulness
   vs plain-LLM and template explanations; hallucination rate.
5. **Controlled human study (N≥16).** Within-subject: EviTaint vs CodeQL output
   vs plain-LLM explanation; tasks = verify/reject findings; measure correctness,
   time, trust calibration, SUS/NASA-TLX. IRB approval; recruit security
   reviewers; responsible disclosure for any real vulnerabilities found.

---

## 6. Threats to validity (current state)

- Probes and benchmark apps are small and partly synthetic; labels follow sink
  semantics, not adjudicated real-world ground truth.
- Dynamic confirmation drives the default execution path only; branch-dependent
  flows may be reported `inconclusive` (by design, not as a positive/negative).
- The confirmation harness mocks frameworks/modules; behavior under a real
  framework can differ.
- Spec inference's verification gate reduces but does not eliminate spurious
  specs; accepted specs should still be reviewed.
- Calibration on a tiny set is optimistic; report held-out ECE in the scaled
  study.
