import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFiles } from '../src/core/engine.js';

const scan = (code, opts) => analyzeFiles({ 'app.js': code }, opts);
const cats = (r) => r.findings.map((f) => f.category).sort();

test('direct source to sink', () => {
  assert.deepEqual(cats(scan("app.get('/a',(req,res)=>res.send(req.query.n))")), ['xss']);
});

test('template literal propagation is detected', () => {
  const r = scan("app.get('/a',(req,res)=>{const n=req.query.n; res.send(`<b>${n}</b>`)})");
  assert.deepEqual(cats(r), ['xss']);
});

test('template literal miss when disabled (prototype behavior)', () => {
  const r = scan("app.get('/a',(req,res)=>{const n=req.query.n; res.send(`<b>${n}</b>`)})", { templateLiterals: false });
  assert.equal(r.findings.length, 0);
});

test('interprocedural cross-function flow', () => {
  const r = scan("function render(res,v){res.send(v)}\napp.get('/a',(req,res)=>render(res,req.query.n))");
  assert.deepEqual(cats(r), ['xss']);
  assert.ok(r.findings[0].interprocedural);
});

test('same-named variables in distinct scopes do not share taint', () => {
  const r = scan("function unsafe(req,res){const value=req.query.x;res.send(value)} function safe(req,res){const value='safe';res.send(value)} app.get('/unsafe',unsafe); app.get('/safe',safe);");
  assert.deepEqual(cats(r), ['xss']);
  assert.equal(r.findings[0].source.label, 'req.query.x');
});

test('cross-file finding has ordered, source-backed trace node identities', () => {
  const r = analyzeFiles({
    'app.js': "import { render } from './render.js'; app.get('/x',(req,res)=>render(res,req.query.x));",
    'render.js': "export function render(res,value){res.send('<b>'+value+'</b')}",
  });
  assert.deepEqual(cats(r), ['xss']);
  const trace = r.findings[0].trace;
  assert.deepEqual(trace.map((step) => step.kind), ['source', 'call', 'param-bind', 'propagate', 'propagate', 'sink']);
  for (const step of trace) {
    assert.match(step.nodeId, /^[a-f0-9]{16}$/);
    assert.equal(step.code, r.project.files[step.file].slice(step.start, step.end).replace(/\s+/g, ' ').slice(0, 140));
  }
  assert.equal(r.findings[0].crossFile, true);
});

test('taint is killed on safe reassignment', () => {
  const r = scan("app.get('/a',(req,res)=>{let n=req.query.n; n='safe'; res.send(n)})");
  assert.equal(r.findings.length, 0);
});

test('persistent taint without kill (prototype false positive)', () => {
  const r = scan("app.get('/a',(req,res)=>{let n=req.query.n; n='safe'; res.send(n)})", { killOnReassign: false });
  assert.equal(r.findings.length, 1);
});

test('sanitizer removes finding and is recorded as suppressed', () => {
  const r = scan("const e=require('escape-html');app.get('/a',(req,res)=>res.send(e(req.query.n)))");
  assert.equal(r.findings.length, 0);
  assert.equal(r.suppressed.length, 1);
});

test('parameterized SQL is safe', () => {
  const r = scan("app.get('/a',(req,res)=>db.query('SELECT * FROM u WHERE id=?',[req.query.id]))");
  assert.equal(r.findings.filter((f) => f.category === 'sqli').length, 0);
});

test('SQL concatenation is flagged', () => {
  const r = scan("app.get('/a',(req,res)=>db.query('SELECT * FROM u WHERE id='+req.query.id))");
  assert.deepEqual(cats(r), ['sqli']);
});

test('command injection through exec', () => {
  const r = scan("const cp=require('child_process');app.post('/a',(req,res)=>cp.exec('ping '+req.body.h,()=>res.end()))");
  assert.deepEqual(cats(r), ['cmdi']);
});

test('allowlist guard sanitizes downstream', () => {
  const r = scan("app.get('/a',(req,res)=>{const f=req.query.f;if(!/^[a-z]+$/.test(f))return res.end();require('fs').readFile('/d/'+f,()=>res.end())})");
  assert.equal(r.findings.length, 0);
});

test('parse failure is a coverage gap, not zero findings', () => {
  const r = analyzeFiles({ 'bad.js': 'function (( {' });
  assert.ok(r.coverage.filesFailed.length + r.coverage.filesPartiallyParsed.length >= 1);
});

test('every finding carries a real source-to-sink trace', () => {
  const r = scan("app.get('/a',(req,res)=>{const n=req.query.n; res.send('<b>'+n+'</b>')})");
  const f = r.findings[0];
  assert.equal(f.trace[0].kind, 'source');
  assert.equal(f.trace[f.trace.length - 1].kind, 'sink');
  for (const s of f.trace) assert.ok(typeof s.line === 'number' && s.start != null);
});

test('prototype pollution via computed assignment', () => {
  const r = scan("app.post('/a',(req,res)=>{const o={};o[req.body.k]=req.body.v;res.end()})");
  assert.ok(r.findings.some((f) => f.category === 'proto'));
});

test('dangerouslySetInnerHTML JSX sink', () => {
  const r = analyzeFiles({ 'c.jsx': "export default function C({req}){const h=req.query.h;return <div dangerouslySetInnerHTML={{__html:h}}/>}" });
  assert.ok(r.findings.some((f) => f.category === 'xss'));
});
