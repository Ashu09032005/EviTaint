const base = '';

export async function analyze(files, options) {
  const r = await fetch(`${base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files, options }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

export async function analyzeUpload(file, options) {
  const fd = new FormData();
  fd.append('project', file);
  fd.append('options', JSON.stringify(options));
  const r = await fetch(`${base}/api/analyze/upload`, { method: 'POST', body: fd });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  return r.json();
}

export async function demo() {
  const r = await fetch(`${base}/api/demo`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
