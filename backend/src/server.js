/**
 * EviTaint HTTP API.
 *
 *   POST /api/analyze        { files:{path:code}, options } -> full report
 *   POST /api/analyze/upload  (multipart zip)              -> full report
 *   POST /api/confirm         { files, finding }           -> one confirmation
 *   POST /api/counterfactual  { files, finding }           -> one counterfactual
 *   GET  /api/demo                                         -> analyze bundled demo
 *   GET  /api/health
 */
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import AdmZip from 'adm-zip';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runPipeline } from './pipeline.js';
import { confirmFinding } from './confirm/harness.js';
import { counterfactual } from './confirm/counterfactual.js';
import { createLLM } from './llm/client.js';
import { toSARIF } from './report/sarif.js';
import { SOURCE_EXTENSIONS } from './core/project.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const llm = createLLM();

app.use(cors());
app.use(express.json({ limit: '12mb' }));

const pipelineOpts = (o = {}) => ({
  interprocedural: o.interprocedural !== false,
  sanitizers: o.sanitizers !== false,
  killOnReassign: o.killOnReassign !== false,
  templateLiterals: o.templateLiterals !== false,
  confirm: Boolean(o.confirm),
  counterfactual: Boolean(o.counterfactual),
  dynamicCounterfactual: Boolean(o.confirm && o.counterfactual),
  inferSpecs: Boolean(o.inferSpecs),
  llm: llm.enabled && o.useLLM ? llm : null,
});

function filesFromZip(buf) {
  const zip = new AdmZip(buf);
  const files = {};
  let prefix = null;
  const entries = zip.getEntries().filter((e) => !e.isDirectory);
  // strip a common top-level folder
  const tops = new Set(entries.map((e) => e.entryName.split('/')[0]));
  if (tops.size === 1) prefix = [...tops][0] + '/';
  for (const e of entries) {
    let name = e.entryName.replace(/\\/g, '/');
    if (name.includes('node_modules/') || name.includes('/.git/')) continue;
    if (!SOURCE_EXTENSIONS.includes(path.extname(name))) continue;
    if (prefix && name.startsWith(prefix)) name = name.slice(prefix.length);
    if (name.endsWith('.min.js')) continue;
    files[name] = e.getData().toString('utf8');
  }
  return files;
}

app.get('/api/health', (_req, res) => res.json({ ok: true, version: '1.0.0', llm: llm.enabled }));

app.post('/api/analyze', async (req, res) => {
  try {
    const { files, options } = req.body;
    if (!files || typeof files !== 'object' || !Object.keys(files).length) return res.status(400).json({ error: 'provide files: { "path": "code" }' });
    const report = await runPipeline(files, pipelineOpts(options));
    res.json(report);
  } catch (e) { res.status(500).json({ error: e.message, stack: process.env.NODE_ENV === 'development' ? e.stack : undefined }); }
});

app.post('/api/analyze/upload', upload.single('project'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'upload a .zip as field "project"' });
    const files = filesFromZip(req.file.buffer);
    if (!Object.keys(files).length) return res.status(400).json({ error: 'no analyzable JS/TS source files found in the archive' });
    const options = req.body.options ? JSON.parse(req.body.options) : {};
    const report = await runPipeline(files, pipelineOpts(options));
    report.meta.uploadedFiles = Object.keys(files).length;
    res.json(report);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/confirm', async (req, res) => {
  try { res.json(await confirmFinding(req.body.finding, req.body.files)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/counterfactual', async (req, res) => {
  try { res.json(await counterfactual(req.body.finding, req.body.files, { dynamic: Boolean(req.body.dynamic) })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sarif', async (req, res) => {
  try { const report = await runPipeline(req.body.files, pipelineOpts(req.body.options)); res.json(toSARIF(report)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/demo', async (_req, res) => {
  try {
    const demoDir = path.join(__dirname, '..', '..', 'benchmark', 'apps', 'vulnerable-express');
    const files = {};
    const walk = (d, base) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const full = path.join(d, e.name); const rel = path.join(base, e.name); if (e.isDirectory()) walk(full, rel); else if (SOURCE_EXTENSIONS.includes(path.extname(e.name))) files[rel.split(path.sep).join('/')] = fs.readFileSync(full, 'utf8'); } };
    if (fs.existsSync(demoDir)) walk(demoDir, '');
    const report = await runPipeline(files, pipelineOpts({ confirm: true, counterfactual: true }));
    res.json(report);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// serve built frontend if present
const dist = path.join(__dirname, '..', 'public');
if (fs.existsSync(dist)) { app.use(express.static(dist)); app.get('*', (_req, res) => res.sendFile(path.join(dist, 'index.html'))); }

const PORT = process.env.PORT || 4000;
if (process.env.NODE_ENV !== 'test') app.listen(PORT, () => console.log(`EviTaint API on http://localhost:${PORT}  (LLM ${llm.enabled ? 'enabled' : 'disabled'})`));

export default app;
