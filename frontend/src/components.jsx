import React from 'react';

export function Pill({ kind, children }) { return <span className={`pill ${kind || ''}`}>{children}</span>; }

export function Meter({ value }) {
  return <div className="meter" title={`${(value * 100).toFixed(1)}%`}><i style={{ width: `${Math.max(2, value * 100)}%` }} /></div>;
}

export function Stat({ n, l }) { return <div className="stat"><div className="n">{n}</div><div className="l">{l}</div></div>; }

export function Trace({ trace }) {
  return (
    <div className="trace">
      {trace.map((s, i) => (
        <div key={i} className={`step ${s.kind}`}>
          <div className="kind">{s.kind.replace(/-/g, ' ')} · {s.file}:{s.line}</div>
          <div className="detail">{s.detail}</div>
          {s.code && <code>{s.code}</code>}
        </div>
      ))}
    </div>
  );
}

export function Claims({ claims }) {
  return (
    <div>
      {claims.map((c) => (
        <div key={c.id} className={`claim ${c.supported ? 'supported' : 'unsupported'}`}>
          <div className="t">{c.supported ? '✓' : '✗'} {typeof c.text === 'string' ? c.text : JSON.stringify(c.text)}</div>
          <div className="c small">{c.evidence.type} — {c.checkDetail}{c.soft ? ' (soft)' : ''}</div>
        </div>
      ))}
    </div>
  );
}

export function Diff({ diff }) {
  if (!diff) return null;
  return (
    <div className="diff">
      <div className="del">- {diff.before}</div>
      <div className="add">+ {diff.after}</div>
    </div>
  );
}

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export function severitySort(a, b) { return (b.confidence.calibrated - a.confidence.calibrated) || (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]); }
