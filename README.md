# EviTaint

**Evidence-Carrying, Counterfactually-Verified Explanations for Taint-Style Vulnerabilities in JavaScript/TypeScript Web Applications**

EviTaint is a research-grade static+dynamic vulnerability analyzer for JS/TS web
apps. Unlike a rule-based prototype that prints a plausible-looking source/sink
pair, every EviTaint finding carries **machine-checkable evidence**: a real
source→sink trace, an explanation whose every claim is verified against the
program, an optional dynamic confirmation, and a counterfactual fix that is
re-analyzed to prove it removes the flow.

It was built to close the evidence gaps identified in a prior prototype
evaluation (missing template-literal / interprocedural propagation, taint that
survives benign reassignment, no sanitizer model, no secret detection, silent
parse failures, random explanation text, severity-metadata mismatch, and the
absence of any labeled evaluation).

---

## What's novel here

| # | Contribution | Where |
|---|---|---|
| **N1** | **Evidence-Carrying Explanations** — explanation = list of atomic claims, each bound to an artifact; a Claim Checker verifies each; prose is generated *only* from verified claims. | `src/explain/` |
| **N2** | **Counterfactual flow verification** — auto-generate a sanitizing patch and a flow-breaking edit, re-analyze (and optionally re-confirm), require the verdict to flip. The patch doubles as a verified fix. | `src/confirm/counterfactual.js` |
| **N3** | **Spec inference with a verification gate** — mined/LLM-proposed sources/sinks/sanitizers are accepted only if a synthetic probe shows the expected effect. | `src/specs/inference.js` |
| **N4** | **Dynamic confirmation via a benign marker** — a harmless canary is injected as request input and run under fully inert mocks; reachability (not exploitation) is observed. No attack payloads are ever generated. | `src/confirm/` |
| **N5** | **Calibrated confidence** — confidence is a feature-based score mapped through a fitted isotonic curve, with ECE/Brier reported. Not a fixed label. | `src/explain/calibration.js` |
| **N6** | **Metric suite** — detection P/R/F1 (bootstrap CIs), trace quality, explanation faithfulness, confirmation & counterfactual rates, calibration. | `scripts/evaluate.js` |
| **N7** | **EviTaint-Bench** — labeled JS/TS web apps with line-level ground truth, true negatives, and annotator agreement. | `benchmark/` |

See [`RESEARCH.md`](./RESEARCH.md) for the full gap→module→experiment mapping,
related-work comparison, and the validation agenda (including the human study).

Each static trace step includes a deterministic AST-node ID, file and source
location, source offsets, code text, and an operation kind. These fields let
the UI and claim checker link evidence back to the exact parsed source node.

---

## Layout

```
evitaint/
├── backend/
│   ├── src/
│   │   ├── core/          project loading, parsing+coverage, taint engine, secret detector
│   │   ├── specs/         default taint specs + gated spec inference
│   │   ├── confirm/       benign-marker reachability harness, inert mocks, counterfactuals
│   │   ├── explain/       claims, claim checker, explainer, calibration
│   │   ├── report/        SARIF export
│   │   ├── llm/           optional (disabled by default) LLM client
│   │   ├── pipeline.js    orchestrator
│   │   ├── server.js      HTTP API
│   │   └── cli.js         command-line scanner
│   ├── scripts/           evaluate.js, calibrate.js
│   └── test/              node:test suite (21 tests)
├── frontend/              Vite + React UI (trace viewer, evidence panel, counterfactual diff)
└── benchmark/
    ├── apps/              vulnerable-express, safe-express, mixed-ts
    ├── labels/            line-level ground truth (+ negatives, annotator agreement)
    └── evaluation_results.json
```

## Quick start

```bash
# Backend
cd backend
npm install
npm test                       # 21 tests
npm run eval -- --confirm      # detection + ablations + calibration metrics
node src/cli.js ../benchmark/apps/vulnerable-express --confirm --counterfactual

# API + UI
npm start                      # serves API on :4000 (and the built UI if present)

# Frontend (dev)
cd ../frontend
npm install
npm run dev                    # http://localhost:5173 (proxies /api to :4000)
npm run build                  # emits to backend/public so `npm start` serves it
```

## CLI

```
evitaint <projectDir> [--confirm] [--counterfactual] [--infer-specs]
                      [--json out.json] [--sarif out.sarif]
```

`--confirm` runs the benign-marker reachability harness; `--counterfactual`
runs the sanitizing-patch / flow-breaking verification; `--infer-specs` mines
and gate-verifies project-specific specs. SARIF output drops into GitHub code
scanning.

## API

| Method | Path | Body |
|---|---|---|
| POST | `/api/analyze` | `{ files:{path:code}, options }` |
| POST | `/api/analyze/upload` | multipart `project=<zip>` |
| POST | `/api/confirm` | `{ files, finding }` |
| POST | `/api/counterfactual` | `{ files, finding }` |
| POST | `/api/sarif` | `{ files, options }` |
| GET | `/api/demo` | analyzes the bundled vulnerable app |
| GET | `/api/health` | — |

`options`: `{ interprocedural, sanitizers, killOnReassign, templateLiterals,
confirm, counterfactual, inferSpecs, useLLM }` (all booleans).

## The optional LLM

The pipeline is **fully functional and deterministic with no API key**. If
`OPENAI_API_KEY` is set and `useLLM` is requested, the LLM is used only to
(a) rephrase already-verified claims — its output is re-gated so it cannot
introduce unverified claims — and (b) propose spec candidates that must then
pass the verification gate. The LLM is never a source of truth.

## Safety note on the confirmation harness

Dynamic confirmation does **not** generate or run exploits. It injects a single
harmless marker token as request input, runs the target route handler under
mocks that replace every dangerous operation (database, shell, filesystem,
network, `eval`) with inert recorders, and checks whether the marker reached a
sink. It verifies *reachability of a taint flow*, not exploitability. Nothing
touches a real database, shell, file, or network socket.

## Reproducibility

Deterministic given the same inputs and options (no randomness in the static
pipeline; explanations are template-based unless the LLM is explicitly enabled).
`npm run eval` writes `benchmark/evaluation_results.json`; `npm run calibrate`
writes `benchmark/calibration.json` with before/after ECE and Brier.

## License

MIT (code). Benchmark apps are deliberately vulnerable and for testing only.
