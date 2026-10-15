import React, { useState } from 'react';
import { analyze, analyzeUpload, demo } from './api.js';
import { Pill, Meter, Stat, Trace, Claims, Diff } from './components.jsx';

const SAMPLE = `const express = require('express');
const cp = require('child_process');
const app = express();

// SQL injection: request input concatenated into a query
app.get('/search', (req, res) => {
  const term = req.query.term;
  db.query('SELECT * FROM products WHERE name = "' + term + '"');
  res.end();
});

// Command injection through a helper (interprocedural)
function run(cmd) { cp.exec(cmd, () => {}); }
app.post('/ping', (req, res) => {
  run('ping ' + req.body.host);
  res.end();
});

// Safe: output is encoded, so no XSS finding
const escape = require('escape-html');
app.get('/hi', (req, res) => res.send('<b>' + escape(req.query.n) + '</b>'));`;

export default function App() {
  const [code, setCode] = useState(SAMPLE);
  const [opts, setOpts] = useState({ interprocedural: true, sanitizers: true, killOnReassign: true, templateLiterals: true, confirm: true, counterfactual: true, inferSpecs: false });
  const [report, setReport] = useState(null);
  const [sel, setSel] = useState(null);
  const [tab, setTab] = useState('findings');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const opt = (k) => (e) => setOpts({ ...opts, [k]: e.target.checked });

  async function go(fn) {
    setLoading(true); setErr(null); setSel(null);
    try { const r = await fn(); setReport(r); setSel(r.findings[0] || null); setTab('findings'); }
    catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  }

  const run = () => go(() => analyze({ 'input.js': code }, opts));
  const runDemo = () => go(() => demo());
  const onUpload = (e) => { const f = e.target.files[0]; if (f) go(() => analyzeUpload(f, opts)); };

  const s = report?.summary;
  const expl = sel && report ? report.explanations[sel.id] : null;
  const conf = sel && report ? report.confirmations[sel.id] : null;
  const cf = sel && report ? report.counterfactuals[sel.id] : null;

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand"><b>EviTaint</b><small>Evidence-carrying, counterfactually-verified taint analysis</small></div>
        <div className="spacer" />
        <span className="tag">JS / TS web apps</span>
        <span className="tag">{report?.meta?.options?.llm ? 'LLM on' : 'deterministic'}</span>
      </div>

      <div className="layout">
        <div className="sidebar">
          <div className="section-title">Source</div>
          <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
          <div className="section-title">Analysis options</div>
          <div className="card" style={{ padding: 12 }}>
            {[['interprocedural', 'Interprocedural (cross-function/file)'], ['sanitizers', 'Sanitizer & guard modeling'], ['killOnReassign', 'Kill taint on safe reassignment'], ['templateLiterals', 'Template-literal propagation'], ['confirm', 'Dynamic confirmation (benign marker)'], ['counterfactual', 'Counterfactual verification'], ['inferSpecs', 'LLM/mined spec inference (gated)']].map(([k, l]) => (
              <label className="opt" key={k}><input type="checkbox" checked={opts[k]} onChange={opt(k)} />{l}</label>
            ))}
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn" onClick={run} disabled={loading}>{loading ? <span className="spin" /> : 'Analyze'}</button>
            <button className="btn secondary" onClick={runDemo} disabled={loading}>Run demo app</button>
          </div>
          <div style={{ marginTop: 12 }}><label className="small">Upload project (.zip): <input type="file" accept=".zip" onChange={onUpload} /></label></div>
          {err && <div className="gap" style={{ marginTop: 12 }}>⚠ {err}</div>}
        </div>

        <div className="main">
          {!report && <div className="empty">Analyze the sample, run the bundled demo app, or upload a project to begin.<br />Every finding comes with a verified source→sink trace, a faithfulness-checked explanation, dynamic confirmation, and a counterfactual fix.</div>}
          {report && (
            <>
              <div className="stat-grid">
                <Stat n={s.total} l="findings" />
                <Stat n={`${s.coverage.parsed}/${s.coverage.discovered}`} l="files parsed" />
                <Stat n={s.confirmed} l="confirmed" />
                <Stat n={s.causallySupported} l="causally supported" />
                <Stat n={s.meanFaithfulness ?? '—'} l="mean faithfulness" />
              </div>

              {(report.coverage.filesFailed.length > 0 || report.coverage.filesPartiallyParsed.length > 0) && (
                <>
                  <div className="section-title">Coverage gaps (not reported as "0 findings")</div>
                  {[...report.coverage.filesFailed, ...report.coverage.filesPartiallyParsed].map((g, i) => (
                    <div className="gap" key={i}>⚠ {g.file}: {g.errors.map((e) => e.message).join(', ')}</div>
                  ))}
                </>
              )}

              <div className="layout" style={{ gridTemplateColumns: '1fr 1fr', gap: 18, marginTop: 10 }}>
                <div>
                  <div className="section-title">Findings</div>
                  {report.findings.length === 0 && <div className="small">No taint flows reached a sink. {report.suppressed.length > 0 && `${report.suppressed.length} candidate(s) were suppressed by sanitizers.`}</div>}
                  {report.findings.map((f) => (
                    <div key={f.id} className={`finding ${sel?.id === f.id ? 'sel' : ''}`} style={{ borderLeftColor: `var(--${f.severity})` }} onClick={() => { setSel(f); setTab('findings'); }}>
                      <div className="head">
                        <span className={`sev ${f.severity}`}>{f.severity}</span>
                        <strong>{f.categoryName}</strong>
                        <span className="small">{f.cwe}</span>
                        <div style={{ flex: 1 }} />
                        {f.confirmation === 'confirmed' && <Pill kind="ok">confirmed</Pill>}
                        {f.confirmation === 'sanitized-at-runtime' && <Pill kind="warn">sanitized@runtime</Pill>}
                        {f.counterfactual === true && <Pill kind="ok">causal</Pill>}
                      </div>
                      <div className="loc">{f.file}:{f.line} · sink {f.sink}{f.route ? ` · ${f.route.method.toUpperCase()} ${f.route.path}` : ''}</div>
                      <div className="row small" style={{ marginTop: 6, gap: 14 }}>
                        <span>conf {f.confidence.calibrated}{f.confidence.uncalibrated ? '~' : ''}</span>
                        <span>faith {f.faithfulness}</span>
                        <span style={{ flex: 1 }}><Meter value={f.confidence.calibrated} /></span>
                      </div>
                    </div>
                  ))}
                </div>

                <div>
                  {sel ? (
                    <>
                      <div className="tabs">
                        {['findings', 'trace', 'claims', 'counterfactual', 'raw'].map((t) => (
                          <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{t === 'findings' ? 'explanation' : t}</button>
                        ))}
                      </div>

                      {tab === 'findings' && (
                        <div className="card">
                          <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                            <span className={`sev ${sel.severity}`}>{sel.severity}</span>
                            <strong>{sel.categoryName}</strong><span className="small">{sel.cwe}</span>
                          </div>
                          <p style={{ marginTop: 0 }}>{expl.prose}</p>
                          <table className="kv">
                            <tbody>
                              <tr><td>faithfulness</td><td>{expl.faithfulness} ({expl.supportedClaims}/{expl.totalClaims} claims verified)</td></tr>
                              <tr><td>confidence</td><td>{sel.confidence.calibrated} {sel.confidence.uncalibrated ? '(uncalibrated — no curve fitted)' : '(calibrated)'} · raw {sel.confidence.raw}</td></tr>
                              <tr><td>dynamic</td><td>{conf ? `${conf.status} — ${conf.reason}` : 'not run'}</td></tr>
                              <tr><td>source</td><td className="small">{sel.source.label} @ {sel.source.file}:{sel.source.line}</td></tr>
                              <tr><td>assumptions</td><td className="small">{sel.assumptions.length ? sel.assumptions.join('; ') : 'none'}</td></tr>
                            </tbody>
                          </table>
                        </div>
                      )}

                      {tab === 'trace' && <div className="card"><div className="small" style={{ marginBottom: 6 }}>Each step resolves to a real AST node and was re-verified against source.</div><Trace trace={sel.trace} /></div>}

                      {tab === 'claims' && <div className="card"><div className="small" style={{ marginBottom: 8 }}>Prose is generated only from claims that passed the checker.</div><Claims claims={expl.claims} /></div>}

                      {tab === 'counterfactual' && (
                        <div className="card">
                          {cf && cf.status !== 'skipped' ? (
                            <>
                              <div className="row" style={{ gap: 8, marginBottom: 10 }}>{cf.causallySupported ? <Pill kind="ok">causally supported</Pill> : <Pill kind="warn">partial</Pill>}</div>
                              <p className="small" style={{ marginTop: 0 }}>{cf.verdict}</p>
                              {cf.sanitizingPatch && (<><div className="section-title">Verified sanitizing fix ({cf.sanitizingPatch.sanitizer}) · static removed: {String(cf.sanitizingPatch.staticFindingRemoved)}</div><Diff diff={cf.sanitizingPatch.diff} /></>)}
                              <div className="section-title">Flow-breaking control edit · static removed: {String(cf.flowBreakingEdit.staticFindingRemoved)}</div>
                              <Diff diff={cf.flowBreakingEdit.diff} />
                            </>
                          ) : <div className="small">Counterfactual verification was not run for this finding{cf?.reason ? ` (${cf.reason})` : ''}.</div>}
                        </div>
                      )}

                      {tab === 'raw' && <div className="card"><pre style={{ margin: 0, fontSize: 11.5, overflow: 'auto', fontFamily: 'var(--mono)' }}>{JSON.stringify(sel, null, 2)}</pre></div>}
                    </>
                  ) : <div className="empty">Select a finding to see its evidence.</div>}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
