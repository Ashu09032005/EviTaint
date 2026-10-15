/**
 * Forked worker: loads the project under inert mocks, drives one route handler
 * with a benign marker token, and reports whether the marker reached the sink.
 *
 * Runs as a CommonJS-style module via createRequire + vm so that both ESM and
 * CJS projects can be loaded uniformly. All module resolution is intercepted;
 * no project code can reach the real fs / child_process / network.
 */
import Module from 'node:module';
import vm from 'node:vm';
import path from 'node:path';
import { createRequire } from 'node:module';
import { transformSync } from '@babel/core';
import { createMocks } from './mocks.js';

const require = createRequire(import.meta.url);

// Unique token used to track whether request input reaches a sink.
// CORE is an opaque id (detects arrival). META is a short run of characters
// that sanitizers neutralize (detects transformation). The combination is a
// passive canary, not a working exploit for any sink.
const CORE = 'EVITAINTCANARY' + Math.random().toString(36).slice(2, 10);
const META = `<"'&;`;
const MARKER = CORE + META;

function reached(category, value, meta, hits) {
  const texts = [];
  const walk = (v, depth = 0) => {
    if (v == null || depth > 4) return;
    if (typeof v === 'string') texts.push(v);
    else if (typeof v === 'object') { for (const k of Object.keys(v)) { texts.push(k); walk(v[k], depth + 1); } }
    else texts.push(String(v));
  };
  walk(value);
  const joined = texts.join('\u0000');
  const hasCore = joined.includes(CORE);
  if (category === 'sqli' && meta.parameterized && !joined.includes(CORE + META)) { hits.push({ category, meta, disposition: 'parameterized' }); return; }
  if (!hasCore) return; // the input never reached this sink on the executed path
  if (joined.includes(MARKER)) hits.push({ category, meta, disposition: 'intact' }); // metacharacters survived unmodified
  else hits.push({ category, meta, disposition: 'transformed' }); // reached sink but neutralized
}

function buildRequire(files, mocks, hits, rootFile) {
  const compiledCache = new Map();
  const resolve = (from, spec) => {
    if (!spec.startsWith('.')) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));
    const exts = ['', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '/index.js', '/index.ts'];
    for (const e of exts) if (files[base + e] !== undefined) return base + e;
    if (/\.js$/.test(base)) for (const e of ['.ts', '.tsx']) if (files[base.replace(/\.js$/, e)] !== undefined) return base.replace(/\.js$/, e);
    return null;
  };

  const makeRequire = (fromFile) => {
    const req = (spec) => {
      const local = resolve(fromFile, spec);
      if (local) return loadModule(local);
      return externalMock(spec);
    };
    req.resolve = (s) => s;
    return req;
  };

  function externalMock(spec) {
    const s = spec.replace(/^node:/, '');
    if (s === 'express') { const f = () => appHub; f.Router = () => appHub; f.static = () => () => {}; f.json = () => () => {}; f.urlencoded = () => () => {}; f.default = f; return f; }
    if (s === 'koa' || s === 'fastify' || s === 'fastify/lib') { function F() { return appHub; } F.default = F; return F; }
    if (s === 'child_process') return mocks.childProcess;
    if (s === 'fs') return mocks.fsProxy;
    if (s === 'fs/promises') return mocks.fsProxy.promises;
    if (s === 'path') return path;
    if (s === 'vm') return { runInNewContext: mocks.codeSink('vm.runInNewContext'), runInThisContext: mocks.codeSink('vm.runInThisContext'), runInContext: mocks.codeSink('vm.runInContext'), createContext: () => ({}), Script: function () { this.runInNewContext = mocks.codeSink('vm.Script'); } };
    if (['mysql', 'mysql2', 'mysql2/promise', 'pg', 'sqlite3', 'better-sqlite3', 'mssql', 'knex', 'sequelize', 'oracledb', 'tedious'].includes(s)) return mocks.dbModule(s);
    if (s === 'mongodb' || s === 'mongoose') return mocks.dbModule(s);
    if (['axios', 'node-fetch', 'got', 'request', 'superagent', 'needle', 'undici'].includes(s)) {
      const c = mocks.httpClient(s); c.get = mocks.httpClient(s + '.get'); c.post = mocks.httpClient(s + '.post'); c.request = mocks.httpClient(s + '.request'); c.default = c; return c;
    }
    if (s === 'http' || s === 'https') return { get: mocks.httpClient(s + '.get'), request: mocks.httpClient(s + '.request'), createServer: () => mocks.stub('server') };
    if (s === 'escape-html' || s === 'he' || s === 'xss' || s === 'sanitize-html' || s === 'dompurify' || s === 'isomorphic-dompurify') {
      const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      const f = (v) => esc(v); f.encode = esc; f.escape = esc; f.sanitize = esc; f.default = f; return f;
    }
    if (s === 'sqlstring' || s === 'mysql-escape') { const f = {}; f.escape = (v) => `'${String(v).replace(/'/g, "''")}'`; f.format = (q, a) => q; return f; }
    if (s === 'shell-quote') return { quote: (a) => a.map((x) => `'${String(x)}'`).join(' ') };
    if (s === 'mongo-sanitize') { const f = (v) => (v && typeof v === 'object' ? {} : v); f.sanitize = f; return f; }
    if (s === 'lodash' || s === 'lodash.merge') return new Proxy(mocks.stub('lodash'), { get: (_t, p) => (p === 'escape' ? (v) => String(v) : mocks.stub('lodash.' + String(p))) });
    return mocks.stub(s);
  }

  function loadModule(file) {
    if (compiledCache.has(file)) return compiledCache.get(file).exports;
    let code = files[file];
    const isTs = /\.(ts|tsx)$/.test(file);
    const needsTransform = isTs || /\b(import|export)\b/.test(code);
    if (needsTransform) {
      code = transformSync(code, {
        filename: file,
        babelrc: false, configFile: false,
        presets: isTs ? [[require('@babel/preset-typescript'), { allowDeclareFields: true, onlyRemoveTypeImports: true }]] : [],
        plugins: [require('@babel/plugin-transform-modules-commonjs')],
        sourceType: 'unambiguous', retainLines: true,
      }).code;
    }
    const mod = { exports: {} };
    compiledCache.set(file, mod);
    const req = makeRequire(file);
    const wrapper = vm.compileFunction(code, ['exports', 'require', 'module', '__filename', '__dirname', 'process', 'global', 'console', 'Buffer', 'setTimeout', 'setInterval', 'setImmediate', '__evitaintApp'], { filename: file });
    wrapper(mod.exports, req, mod, file, path.posix.dirname(file), fakeProcess, globalThis, safeConsole, Buffer, () => {}, () => {}, (fn) => setImmediate(fn), appHub);
    return mod.exports;
  }

  const routes = [];
  const register = (method) => (p, ...handlers) => { if (typeof p === 'string') routes.push({ method, path: p, handlers: handlers.filter((h) => typeof h === 'function') }); return appHub; };
  const appHub = new Proxy(function () {}, {
    get(_t, prop) {
      const m = String(prop);
      if (['get', 'post', 'put', 'patch', 'delete', 'del', 'all', 'options', 'head', 'use'].includes(m)) {
        return m === 'use' ? () => appHub : register(m === 'del' ? 'delete' : m);
      }
      if (m === 'listen') return (..._a) => { const cb = _a.find((x) => typeof x === 'function'); if (cb) cb(); return mocks.stub('server'); };
      if (m === 'route') return () => appHub;
      if (m === 'set' || m === 'engine' || m === 'enable' || m === 'disable') return () => appHub;
      return mocks.stub('app.' + m);
    },
    apply() { return appHub; },
  });
  const fakeProcess = { ...process, env: { ...process.env, NODE_ENV: 'test' }, argv: ['node', 'app', MARKER], exit: () => {}, on: () => {}, cwd: () => '/' };
  const safeConsole = { log: () => {}, error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

  return { loadModule, routes, appHub, makeRequire };
}

function markerValue(finding) {
  // Build a benign request object whose relevant field carries the marker.
  const field = finding.source.field;
  const sub = finding.source.path || [];
  const setDeep = (obj, keys, val) => { let o = obj; for (let i = 0; i < keys.length - 1; i++) { o[keys[i]] = o[keys[i]] || {}; o = o[keys[i]]; } if (keys.length) o[keys[keys.length - 1]] = val; return obj; };
  return { field, sub };
}

process.on('message', (msg) => {
  const { files, finding } = msg;
  const hits = [];
  const mocks = createMocks((cat, val, meta) => reached(cat, val, meta, hits));
  try {
    const rootCandidates = Object.keys(files).filter((f) => /server|app|index|main/i.test(f)).concat(Object.keys(files));
    const env = buildRequire(files, mocks, hits, rootCandidates[0]);
    // Load modules until routes are registered.
    for (const f of rootCandidates) { try { env.loadModule(f); } catch { /* keep going */ } if (env.routes.length) break; }
    const routes = env.routes;
    const target = routes.find((r) => r.path === finding.route.path && r.method === finding.route.method) || routes.find((r) => r.path === finding.route.path) || routes[0];
    if (!target) { process.send({ status: 'inconclusive', reason: 'route handler not registered when project was loaded under mocks' }); return; }

    const { field, sub } = markerValue(finding);
    const put = (base) => { let o = base; const keys = sub.length ? sub : []; if (!keys.length) return MARKER; for (let i = 0; i < keys.length - 1; i++) { o[keys[i]] = {}; o = o[keys[i]]; } o[keys[keys.length - 1]] = MARKER; return base; };
    const fld = (name) => (['body', 'query', 'params', 'headers', 'cookies'].includes(name) ? (sub.length ? put({}) : { marker: MARKER, [sub[0] || 'value']: MARKER }) : MARKER);
    const req = {
      body: field === 'body' ? fld('body') : {}, query: field === 'query' ? fld('query') : {}, params: field === 'params' ? fld('params') : {},
      headers: field === 'headers' ? fld('headers') : {}, cookies: field === 'cookies' ? fld('cookies') : {},
      get: (h) => (field === 'headers' ? MARKER : ''), header: (h) => (field === 'headers' ? MARKER : ''), param: (p) => (field === 'params' || field === 'query' ? MARKER : ''),
      path: '/', url: '/', originalUrl: '/', method: target.method.toUpperCase(), ip: '127.0.0.1',
    };
    if (field === 'body' && !sub.length) req.body = { marker: MARKER };

    let responded = false;
    const res = new Proxy({}, {
      get(_t, p) {
        const m = String(p);
        if (['send', 'write', 'end', 'json', 'jsonp'].includes(m)) return (v) => { reached('xss', v, { api: `res.${m}` }, hits); responded = true; return res; };
        if (m === 'redirect') return (...a) => { reached('redirect', a[a.length - 1], { api: 'res.redirect' }, hits); responded = true; return res; };
        if (m === 'sendFile' || m === 'download') return (v) => { reached('path', v, { api: `res.${m}` }, hits); responded = true; return res; };
        if (['status', 'set', 'header', 'type', 'cookie', 'append', 'vary', 'location', 'links'].includes(m)) return () => res;
        if (m === 'headersSent') return responded;
        return () => res;
      },
    });
    const next = (e) => {};

    const report = () => {
      const intact = hits.filter((h) => h.category === finding.category && h.disposition === 'intact');
      const neutral = hits.filter((h) => h.category === finding.category && (h.disposition === 'transformed' || h.disposition === 'parameterized'));
      if (intact.length) process.send({ status: 'confirmed', reason: `benign marker reached ${finding.category} sink unmodified`, evidence: intact.slice(0, 3), markerReachedSink: true });
      else if (neutral.length) process.send({ status: 'sanitized-at-runtime', reason: 'marker reached the sink only in neutralized/parameterized form', evidence: neutral.slice(0, 3) });
      else if (responded || hits.length) process.send({ status: 'not-reached', reason: 'handler executed but the marker did not reach this sink on the default path', otherHits: hits.length });
      else process.send({ status: 'inconclusive', reason: 'handler executed without reaching any instrumented sink (input-dependent branch not taken)' });
    };
    const cap = Math.min(msg.timeoutMs || 1500, 1500);
    const t0 = Date.now();
    Promise.resolve().then(() => target.handlers[target.handlers.length - 1](req, res, next)).catch(() => {});
    // Resolve as soon as the relevant sink is hit; otherwise poll until the cap.
    const poll = () => {
      const done = hits.some((h) => h.category === finding.category);
      if ((done && Date.now() - t0 > 60) || Date.now() - t0 >= cap) report();
      else setTimeout(poll, 50);
    };
    setTimeout(poll, 60);
  } catch (e) {
    process.send({ status: 'error', reason: String(e && e.message || e).slice(0, 300) });
  }
});
