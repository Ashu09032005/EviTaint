/**
 * EviTaint taint engine.
 *
 * - Bindings are tracked by scope identity (Babel bindings), not by name.
 * - Flow-sensitive within a function: statements are processed in order;
 *   branches are analyzed on copies of the state and merged (may-analysis);
 *   loops are iterated twice; reassignment with a clean value kills taint.
 * - Interprocedural: every function gets a summary (param->return,
 *   param->sink). Summaries are applied at call sites, across files
 *   (CommonJS + ESM imports).
 * - Every flow carries an ordered list of evidence steps
 *   (file, line, column, node offsets, code text), so a finding's trace is a
 *   real path through the program rather than a constructed string.
 */
import crypto from 'node:crypto';
import { CATEGORIES, SOURCES, CALL_SINKS, ASSIGN_SINKS, SANITIZERS, PROPAGATORS } from '../specs/defaultSpecs.js';
import { buildProject, resolveModule, packageAlias } from './project.js';

export const DEFAULT_OPTIONS = {
  interprocedural: true,
  killOnReassign: true,
  sanitizers: true,
  templateLiterals: true,
  unknownCallPolicy: 'propagate', // 'propagate' | 'drop'
  extraSpecs: null, // { sinks: [...], sanitizers: [...], sources: [...] } from spec inference
};

const MAX_FLOWS = 6;
const MAX_STEPS = 40;
const STRING_PROPAGATORS = new Set(['trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'concat', 'replace', 'replaceAll', 'slice', 'substring', 'substr', 'padStart', 'padEnd', 'toString', 'normalize', 'join', 'format', 'util.format']);
const ITER_METHODS = new Set(['forEach', 'map', 'filter', 'some', 'every', 'find', 'findIndex', 'flatMap']);
const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'del', 'all', 'use', 'options', 'head']);
const NEST_SOURCE_DECORATORS = { Body: 'body', Query: 'query', Param: 'params', Headers: 'headers', Req: null, Request: null };

const isFnNode = (n) => n && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ClassMethod', 'ObjectMethod', 'ClassPrivateMethod'].includes(n.type);

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------
function originKey(o) { return o.kind === 'param' ? `p${o.index}` : `s:${o.label}:${o.step?.start ?? ''}:${o.step?.file ?? ''}`; }

function mkFlow(origin, steps, extra = {}) {
  return { origin, steps, sanitized: extra.sanitized || [], assumptions: extra.assumptions || [], refinable: extra.refinable ?? true, typeHint: extra.typeHint || null };
}

function union(...vals) {
  const out = []; const seen = new Set();
  for (const v of vals) {
    if (!v) continue;
    for (const f of v) {
      const k = originKey(f.origin) + '|' + f.sanitized.join(',');
      if (seen.has(k)) continue;
      seen.add(k); out.push(f);
      if (out.length >= MAX_FLOWS) return out;
    }
  }
  return out;
}

function extend(val, step, mods = {}) {
  if (!val || !val.length) return [];
  return val.map((f) => ({
    ...f,
    steps: f.steps.length >= MAX_STEPS ? f.steps : [...f.steps, step],
    refinable: mods.refinable ?? false,
    typeHint: mods.typeHint ?? f.typeHint,
    sanitized: mods.sanitize ? [...new Set([...f.sanitized, ...mods.sanitize])] : f.sanitized,
    assumptions: mods.assume ? [...f.assumptions, mods.assume] : f.assumptions,
    origin: mods.refine && f.refinable && f.origin.kind === 'source' ? { ...f.origin, path: [...(f.origin.path || []), mods.refine], label: `${f.origin.label}.${mods.refine}` } : f.origin,
  }));
}

const isSanitizedFor = (flow, cat) => flow.sanitized.includes('*') || flow.sanitized.includes(cat);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
class State {
  constructor(parent = null, map = new Map()) { this.parent = parent; this.map = map; }
  get(k) { if (this.map.has(k)) return this.map.get(k); return this.parent ? this.parent.get(k) : []; }
  set(k, v) { this.map.set(k, v); }
  clone() { return new State(this.parent, new Map(this.map)); }
  static merge(a, b) {
    const out = new State(a.parent, new Map());
    const keys = new Set([...a.map.keys(), ...b.map.keys()]);
    for (const k of keys) out.map.set(k, union(a.get(k), b.get(k)));
    return out;
  }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------
export class TaintEngine {
  constructor(project, options = {}) {
    this.project = project;
    this.opts = { ...DEFAULT_OPTIONS, ...options };
    this.bindingIds = new WeakMap();
    this.nextBinding = 1;
    this.summaries = new Map(); // fnKey -> summary
    this.inProgress = new Set();
    this.inlineAnalyzed = new Set();
    this.findings = new Map();
    this.suppressed = new Map();
    this.routes = new Map(); // fnKey -> {method, path, file, line}
    this.unresolvedCalls = new Map(); // callee -> {count, module, sites}
    this.stats = { functionsAnalyzed: 0, summariesApplied: 0, unknownCalls: 0 };
    this.sinks = [...CALL_SINKS, ...(this.opts.extraSpecs?.sinks || [])];
    this.sanitizers = [...SANITIZERS, ...(this.opts.extraSpecs?.sanitizers || [])];
  }

  // ---------- identity / text ----------
  bindingKey(path, name) {
    const b = path.scope.getBinding(name);
    if (!b) return `g:${name}`;
    if (!this.bindingIds.has(b)) this.bindingIds.set(b, `b${this.nextBinding++}:${name}`);
    return this.bindingIds.get(b);
  }
  fnKey(file, node) { return `${file}:${node.start}-${node.end}`; }

  text(file, node, max = 140) {
    const code = this.project.files[file];
    let t = code.slice(node.start, node.end).replace(/\s+/g, ' ');
    if (t.length > max) t = t.slice(0, max - 1) + '…';
    return t;
  }

  step(ctx, node, kind, detail) {
    const nodeId = crypto.createHash('sha1')
      .update(`${ctx.file}:${node.type}:${node.start}:${node.end}`)
      .digest('hex')
      .slice(0, 16);
    return { nodeId, kind, file: ctx.file, line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0, start: node.start, end: node.end, code: this.text(ctx.file, node), detail };
  }

  /** Static member chain, e.g. req.body.name -> ['req','body','name'] (null if dynamic). */
  chain(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return [node.name];
    if (node.type === 'ThisExpression') return ['this'];
    if (node.type === 'TSNonNullExpression' || node.type === 'TSAsExpression' || node.type === 'ParenthesizedExpression') return this.chain(node.expression);
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const obj = this.chain(node.object);
      if (!obj) return null;
      if (!node.computed && node.property.type === 'Identifier') return [...obj, node.property.name];
      if (node.computed && node.property.type === 'StringLiteral') return [...obj, node.property.value];
      if (node.property.type === 'PrivateName') return [...obj, '#' + node.property.id.name];
      return null;
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral') {
      return [packageAlias({ module: node.arguments[0].value, imported: '*' }) || node.arguments[0].value];
    }
    return null;
  }

  /** Canonical callee text with import aliases applied (cp.exec -> child_process.exec). */
  calleeText(ctx, calleePath) {
    const node = calleePath.node;
    const ch = this.chain(node);
    if (!ch) return null;
    const mod = this.project.modules.get(ctx.file);
    const first = ch[0];
    const imp = mod?.imports.get(first);
    if (imp && calleePath.scope.getBinding(first)?.scope.path.isProgram()) {
      const alias = packageAlias(imp);
      if (alias) return [alias, ...ch.slice(1)].join('.');
    }
    return ch.join('.');
  }

  // ---------- sources ----------
  sourceFromChain(ch) {
    if (!ch || ch.length < 2) return null;
    const [a, b, c] = ch;
    if ((a === 'req' || a === 'request') && SOURCES.requestProps.includes(b)) return { label: ch.slice(0, 2).join('.'), field: b, path: ch.slice(2) };
    if (a === 'ctx' && b === 'request' && c && SOURCES.requestProps.includes(c)) return { label: ch.slice(0, 3).join('.'), field: c, path: ch.slice(3) };
    if (a === 'ctx' && ['query', 'params', 'headers', 'cookies'].includes(b)) return { label: ch.slice(0, 2).join('.'), field: b, path: ch.slice(2) };
    const joined = ch.join('.');
    for (const s of [...SOURCES.browser, ...SOURCES.process]) {
      if (joined === s || joined.startsWith(s + '.')) return { label: s, field: s, path: [] };
    }
    for (const s of this.opts.extraSpecs?.sources || []) if (joined === s || joined.startsWith(s + '.')) return { label: s, field: s, path: [] };
    return null;
  }

  sourceFlow(ctx, node, src) {
    const label = [src.label, ...src.path].join('.');
    const step = this.step(ctx, node, 'source', `untrusted input ${label}`);
    return [mkFlow({ kind: 'source', label, field: src.field, path: src.path, step, fn: ctx.fnKey, file: ctx.file }, [step], { refinable: true })];
  }

  // ---------- function summaries ----------
  resolveFunction(ctx, calleePath) {
    const node = calleePath.node;
    const mod = this.project.modules.get(ctx.file);
    const fromModule = (spec, name) => {
      const target = resolveModule(ctx.file, spec, this.project.fileSet);
      if (!target) return null;
      const tm = this.project.modules.get(target);
      let fp = tm?.exports.get(name);
      if (!fp && name === '*') fp = tm?.exports.get('default');
      if (typeof fp === 'string') fp = tm.localFns.get(fp);
      return fp ? { path: fp, file: target } : null;
    };
    if (node.type === 'Identifier') {
      const b = calleePath.scope.getBinding(node.name);
      if (!b) return null;
      const bp = b.path;
      if (isFnNode(bp.node)) return { path: bp, file: ctx.file };
      if (bp.isVariableDeclarator() && isFnNode(bp.node.init)) return { path: bp.get('init'), file: ctx.file };
      const imp = mod?.imports.get(node.name);
      if (imp && b.scope.path.isProgram()) return fromModule(imp.module, imp.imported === '*' ? 'default' : imp.imported);
      return null;
    }
    if (node.type === 'MemberExpression' && !node.computed && node.object.type === 'Identifier') {
      const imp = mod?.imports.get(node.object.name);
      if (imp && imp.imported === '*') return fromModule(imp.module, node.property.name);
      if (imp && imp.imported === 'default') return fromModule(imp.module, node.property.name);
      // local object literal with methods: const utils = { f() {} }
      const b = calleePath.scope.getBinding(node.object.name);
      if (b?.path.isVariableDeclarator() && b.path.node.init?.type === 'ObjectExpression') {
        const props = b.path.get('init.properties');
        for (const p of props) {
          const key = p.node.key?.name || p.node.key?.value;
          if (key !== node.property.name) continue;
          if (p.node.type === 'ObjectMethod') return { path: p, file: ctx.file };
          if (isFnNode(p.node.value)) return { path: p.get('value'), file: ctx.file };
        }
      }
    }
    return null;
  }

  summarize(fnPath, file) {
    const key = this.fnKey(file, fnPath.node);
    if (this.summaries.has(key)) return this.summaries.get(key);
    if (this.inProgress.has(key)) return { returns: [], sinkEffects: [], recursive: true };
    this.inProgress.add(key);
    const summary = { returns: [], sinkEffects: [], name: this.fnName(fnPath) };
    const ctx = { file, fnKey: key, summary, fnPath };
    const state = new State();
    fnPath.get('params').forEach((pp, i) => this.bindParam(ctx, pp, state, i));
    this.stats.functionsAnalyzed++;
    this.analyzeBody(ctx, fnPath, state);
    this.inProgress.delete(key);
    this.summaries.set(key, summary);
    return summary;
  }

  fnName(fnPath) {
    const n = fnPath.node;
    if (n.id?.name) return n.id.name;
    if (n.key?.name) return n.key.name;
    if (fnPath.parentPath?.isVariableDeclarator()) return fnPath.parent.id.name;
    if (fnPath.parentPath?.isObjectProperty()) return fnPath.parent.key.name;
    return '<anonymous>';
  }

  bindParam(ctx, pp, state, index, value = null) {
    let node = pp.node;
    if (node.type === 'TSParameterProperty') { pp = pp.get('parameter'); node = pp.node; }
    let val = value;
    // NestJS-style decorated params: @Body() dto, @Query('q') q
    for (const d of node.decorators || []) {
      const call = d.expression; const name = call.callee?.name || call.name;
      if (name in NEST_SOURCE_DECORATORS) {
        const field = NEST_SOURCE_DECORATORS[name] || 'request';
        const sub = call.arguments?.[0]?.type === 'StringLiteral' ? [call.arguments[0].value] : [];
        val = this.sourceFlow(ctx, node, { label: `req.${field}`, field, path: sub });
      }
    }
    if (val === null && ctx.summary) {
      const step = this.step(ctx, node, 'param', `parameter #${index} of ${ctx.summary.name}`);
      val = [mkFlow({ kind: 'param', index }, [step], { refinable: false })];
    }
    this.bindPattern(ctx, pp, val || [], state, 'param');
  }

  /** Bind a pattern (identifier / destructuring) to a value. */
  bindPattern(ctx, pp, val, state, how = 'assign', kill = true) {
    const node = pp.node;
    if (!node) return;
    if (node.type === 'Identifier') {
      const key = this.bindingKey(pp, node.name);
      const bStep = this.step(ctx, node, how === 'param' ? 'param-bind' : 'assign', `${node.name} receives tainted value`);
      bStep.varName = node.name;
      const newVal = val.length ? extend(val, bStep, { refinable: val.every((f) => f.refinable) }) : [];
      if (!val.length && !(kill && this.opts.killOnReassign)) return; // without kill semantics old taint persists
      state.set(key, (kill && this.opts.killOnReassign) ? newVal : union(state.get(key), newVal));
      return;
    }
    if (node.type === 'AssignmentPattern') {
      const def = this.evalExpr(ctx, pp.get('right'), state);
      return this.bindPattern(ctx, pp.get('left'), union(val, def), state, how, kill);
    }
    if (node.type === 'ObjectPattern') {
      pp.get('properties').forEach((prop) => {
        if (prop.node.type === 'RestElement') return this.bindPattern(ctx, prop.get('argument'), val, state, how, kill);
        const k = prop.node.key?.name ?? prop.node.key?.value;
        const sub = val.length ? extend(val, this.step(ctx, prop.node, 'destructure', `property ${k} destructured`), { refine: k, refinable: true }) : [];
        this.bindPattern(ctx, prop.get('value'), sub, state, how, kill);
      });
      return;
    }
    if (node.type === 'ArrayPattern') {
      pp.get('elements').forEach((el) => { if (el.node) this.bindPattern(ctx, el, val, state, how, kill); });
      return;
    }
    if (node.type === 'RestElement') return this.bindPattern(ctx, pp.get('argument'), val, state, how, kill);
    if (node.type === 'TSParameterProperty') return this.bindPattern(ctx, pp.get('parameter'), val, state, how, kill);
  }

  // ---------- statements ----------
  analyzeBody(ctx, fnPath, state) {
    const body = fnPath.get('body');
    if (body.isBlockStatement()) this.analyzeBlock(ctx, body.get('body'), state);
    else {
      const v = this.evalExpr(ctx, body, state);
      this.recordReturn(ctx, v, body.node);
    }
  }

  recordReturn(ctx, val, node) {
    if (!ctx.summary || !val.length) return;
    const step = this.step(ctx, node, 'return', `returned from ${ctx.summary.name}`);
    ctx.summary.returns = union(ctx.summary.returns, extend(val, step, { refinable: false }));
  }

  analyzeBlock(ctx, stmts, state) {
    for (const s of stmts) {
      const r = this.analyzeStmt(ctx, s, state);
      if (r === 'exit') return 'exit';
    }
    return null;
  }

  analyzeStmt(ctx, sp, state) {
    const n = sp.node;
    switch (n.type) {
      case 'VariableDeclaration':
        sp.get('declarations').forEach((d) => {
          const init = d.get('init');
          if (!init.node) return;
          if (isFnNode(init.node)) return; // summarized on demand
          const v = this.evalExpr(ctx, init, state);
          this.bindPattern(ctx, d.get('id'), v, state, 'assign', true);
        });
        return null;
      case 'ExpressionStatement': this.evalExpr(ctx, sp.get('expression'), state); return null;
      case 'ReturnStatement': {
        if (n.argument) this.recordReturn(ctx, this.evalExpr(ctx, sp.get('argument'), state), n.argument);
        return 'exit';
      }
      case 'ThrowStatement': if (n.argument) this.evalExpr(ctx, sp.get('argument'), state); return 'exit';
      case 'BlockStatement': return this.analyzeBlock(ctx, sp.get('body'), state);
      case 'IfStatement': {
        this.evalExpr(ctx, sp.get('test'), state);
        const guard = this.opts.sanitizers ? this.guardInfo(ctx, sp) : null;
        const a = state.clone(); const b = state.clone();
        const ra = this.analyzeStmtOrBlock(ctx, sp.get('consequent'), a);
        const rb = n.alternate ? this.analyzeStmtOrBlock(ctx, sp.get('alternate'), b) : null;
        let merged;
        if (ra === 'exit' && rb !== 'exit') merged = b;
        else if (rb === 'exit' && ra !== 'exit') merged = a;
        else merged = State.merge(a, b);
        state.map = merged.map;
        // allowlist guard: if (!/^...$/.test(x)) return;  => x is safe afterwards
        if (guard && ra === 'exit' && !n.alternate) {
          for (const key of guard.keys) state.set(key, extend(state.get(key), guard.step, { sanitize: ['*'] }));
        }
        return ra === 'exit' && rb === 'exit' ? 'exit' : null;
      }
      case 'ForStatement': case 'WhileStatement': case 'DoWhileStatement': {
        if (n.init) sp.get('init').isVariableDeclaration() ? this.analyzeStmt(ctx, sp.get('init'), state) : this.evalExpr(ctx, sp.get('init'), state);
        for (let i = 0; i < 2; i++) {
          if (n.test) this.evalExpr(ctx, sp.get('test'), state);
          const s = state.clone(); this.analyzeStmtOrBlock(ctx, sp.get('body'), s);
          state.map = State.merge(state, s).map;
          if (n.update) this.evalExpr(ctx, sp.get('update'), state);
        }
        return null;
      }
      case 'ForOfStatement': case 'ForInStatement': {
        const right = this.evalExpr(ctx, sp.get('right'), state);
        const val = n.type === 'ForInStatement' ? extend(right, this.step(ctx, n.left, 'propagate', 'key of tainted object')) : extend(right, this.step(ctx, n.left, 'propagate', 'element of tainted collection'));
        for (let i = 0; i < 2; i++) {
          const left = sp.get('left');
          if (left.isVariableDeclaration()) this.bindPattern(ctx, left.get('declarations.0.id'), val, state, 'assign', true);
          else this.bindPattern(ctx, left, val, state, 'assign', true);
          const s = state.clone(); this.analyzeStmtOrBlock(ctx, sp.get('body'), s);
          state.map = State.merge(state, s).map;
        }
        return null;
      }
      case 'TryStatement': {
        this.analyzeStmtOrBlock(ctx, sp.get('block'), state);
        if (n.handler) { const s = state.clone(); this.analyzeStmtOrBlock(ctx, sp.get('handler.body'), s); state.map = State.merge(state, s).map; }
        if (n.finalizer) this.analyzeStmtOrBlock(ctx, sp.get('finalizer'), state);
        return null;
      }
      case 'SwitchStatement': {
        this.evalExpr(ctx, sp.get('discriminant'), state);
        let acc = state.clone();
        sp.get('cases').forEach((c) => { const s = state.clone(); this.analyzeBlock(ctx, c.get('consequent'), s); acc = State.merge(acc, s); });
        state.map = acc.map; return null;
      }
      case 'LabeledStatement': return this.analyzeStmt(ctx, sp.get('body'), state);
      case 'ExportNamedDeclaration': case 'ExportDefaultDeclaration': {
        const d = sp.get('declaration');
        if (d.node && !isFnNode(d.node) && d.node.type !== 'ClassDeclaration') {
          if (d.isStatement() || d.isDeclaration()) return this.analyzeStmt(ctx, d, state);
          this.evalExpr(ctx, d, state);
        }
        return null;
      }
      default: return null; // function/class declarations analyzed separately
    }
  }

  analyzeStmtOrBlock(ctx, sp, state) {
    return sp.isBlockStatement() ? this.analyzeBlock(ctx, sp.get('body'), state) : this.analyzeStmt(ctx, sp, state);
  }

  /** Recognize `if (!ALLOW.test(x))`, `if (!list.includes(x))`, `if (!validator.isX(x))` guards. */
  guardInfo(ctx, ifPath) {
    let test = ifPath.get('test');
    if (!(test.isUnaryExpression({ operator: '!' }))) return null;
    test = test.get('argument');
    if (!test.isCallExpression()) return null;
    const callee = test.node.callee;
    const method = callee.type === 'MemberExpression' ? callee.property.name : callee.name;
    const okRegex = method === 'test' && (callee.object?.type === 'RegExpLiteral' || /^[A-Z_]+$|regex|pattern|re$/i.test(callee.object?.name || ''));
    const okAllow = method === 'includes' || method === 'has';
    const okValidator = /^is[A-Z]/.test(method || '') && method !== 'isArray';
    if (!(okRegex || okAllow || okValidator)) return null;
    const argPath = test.get('arguments.0');
    if (!argPath?.node || argPath.node.type !== 'Identifier') return null;
    return { keys: [this.bindingKey(argPath, argPath.node.name)], step: this.step(ctx, ifPath.node.test, 'sanitizer', `validated by guard ${this.text(ctx.file, ifPath.node.test, 60)} (all categories)`) };
  }

  // ---------- expressions ----------
  evalExpr(ctx, ep, state) {
    const n = ep.node;
    if (!n) return [];
    switch (n.type) {
      case 'Identifier': {
        if (n.name === 'undefined') return [];
        return state.get(this.bindingKey(ep, n.name));
      }
      case 'StringLiteral': case 'NumericLiteral': case 'BooleanLiteral': case 'NullLiteral': case 'RegExpLiteral': case 'BigIntLiteral': case 'ThisExpression': case 'Super':
        return [];
      case 'TemplateLiteral': {
        const vals = ep.get('expressions').map((e) => this.evalExpr(ctx, e, state));
        if (!this.opts.templateLiterals) return [];
        return extend(union(...vals), this.step(ctx, n, 'propagate', 'interpolated into template literal'), { typeHint: 'string' });
      }
      case 'TaggedTemplateExpression': {
        const vals = ep.get('quasi.expressions').map((e) => this.evalExpr(ctx, e, state));
        const tag = this.chain(n.tag)?.join('.') || '';
        const safe = /^(sql|SQL|Prisma\.sql|sql\.query|html|safeHtml)$/.test(tag);
        return extend(union(...vals), this.step(ctx, n, safe ? 'sanitizer' : 'propagate', safe ? `parameterized by tagged template ${tag}` : `tagged template ${tag}`), safe ? { sanitize: tag.toLowerCase().includes('html') ? ['xss'] : ['sqli'] } : { typeHint: 'string' });
      }
      case 'BinaryExpression': {
        const l = this.evalExpr(ctx, ep.get('left'), state); const r = this.evalExpr(ctx, ep.get('right'), state);
        if (n.operator === '+') return extend(union(l, r), this.step(ctx, n, 'propagate', 'string concatenation'), { typeHint: 'string' });
        return [];
      }
      case 'LogicalExpression': return union(this.evalExpr(ctx, ep.get('left'), state), this.evalExpr(ctx, ep.get('right'), state));
      case 'ConditionalExpression': this.evalExpr(ctx, ep.get('test'), state); return union(this.evalExpr(ctx, ep.get('consequent'), state), this.evalExpr(ctx, ep.get('alternate'), state));
      case 'UnaryExpression': this.evalExpr(ctx, ep.get('argument'), state); return [];
      case 'UpdateExpression': return [];
      case 'SequenceExpression': { let v = []; ep.get('expressions').forEach((e) => { v = this.evalExpr(ctx, e, state); }); return v; }
      case 'AwaitExpression': case 'TSAsExpression': case 'TSNonNullExpression': case 'ParenthesizedExpression': case 'TSTypeAssertion': case 'TSSatisfiesExpression': case 'YieldExpression':
        return n.argument || n.expression ? this.evalExpr(ctx, ep.get(n.argument ? 'argument' : 'expression'), state) : [];
      case 'ArrayExpression': {
        const vals = ep.get('elements').map((e) => (e.node ? this.evalExpr(ctx, e, state) : []));
        const u = union(...vals);
        return u.length ? extend(u, this.step(ctx, n, 'propagate', 'placed in array'), { refinable: false }) : [];
      }
      case 'ObjectExpression': {
        const vals = ep.get('properties').map((p) => {
          if (p.node.type === 'SpreadElement') return this.evalExpr(ctx, p.get('argument'), state);
          if (p.node.type === 'ObjectMethod') return [];
          if (p.node.computed) this.evalExpr(ctx, p.get('key'), state);
          return this.evalExpr(ctx, p.get('value'), state);
        });
        const u = union(...vals);
        return u.length ? extend(u, this.step(ctx, n, 'propagate', 'placed in object literal'), { refinable: false }) : [];
      }
      case 'SpreadElement': return this.evalExpr(ctx, ep.get('argument'), state);
      case 'MemberExpression': case 'OptionalMemberExpression': return this.evalMember(ctx, ep, state);
      case 'AssignmentExpression': return this.evalAssign(ctx, ep, state);
      case 'CallExpression': case 'OptionalCallExpression': case 'NewExpression': return this.evalCall(ctx, ep, state);
      case 'FunctionExpression': case 'ArrowFunctionExpression': return [];
      case 'JSXElement': case 'JSXFragment': this.evalJSX(ctx, ep, state); return [];
      case 'ClassExpression': return [];
      default: return [];
    }
  }

  evalMember(ctx, ep, state) {
    const n = ep.node;
    const ch = this.chain(n);
    const src = this.sourceFromChain(ch);
    if (src) return this.sourceFlow(ctx, n, src);
    if (n.computed) this.evalExpr(ctx, ep.get('property'), state);
    const obj = this.evalExpr(ctx, ep.get('object'), state);
    if (!obj.length) return [];
    const prop = !n.computed && n.property.type === 'Identifier' ? n.property.name : (n.property.type === 'StringLiteral' ? n.property.value : null);
    if (prop === 'length') return [];
    return extend(obj, this.step(ctx, n, 'propagate', `property ${prop ?? '[computed]'} of tainted object`), { refine: prop || undefined, refinable: prop ? undefined : false });
  }

  evalAssign(ctx, ep, state) {
    const n = ep.node;
    const left = ep.get('left');
    let val = this.evalExpr(ctx, ep.get('right'), state);
    if (n.operator !== '=') {
      const old = this.evalExpr(ctx, left, state);
      val = extend(union(old, val), this.step(ctx, n, 'propagate', `compound assignment ${n.operator}`), { typeHint: 'string' });
    }
    if (left.isIdentifier()) {
      const key = this.bindingKey(left, left.node.name);
      if (!val.length) { if (this.opts.killOnReassign && n.operator === '=') state.set(key, []); return []; }
      const aStep = this.step(ctx, n, 'assign', `${left.node.name} reassigned with tainted value`);
      aStep.varName = left.node.name;
      const nv = extend(val, aStep, { refinable: val.every((f) => f.refinable) });
      state.set(key, this.opts.killOnReassign && n.operator === '=' ? nv : union(state.get(key), nv));
      return val;
    }
    if (left.isMemberExpression()) {
      const ch = this.chain(left.node);
      const prop = !left.node.computed ? left.node.property.name : null;
      // assignment sinks
      for (const s of ASSIGN_SINKS) {
        const full = ch?.join('.');
        const hit = (s.prop && prop && s.prop.includes(prop)) || (s.member && full && s.member.includes(full));
        if (hit && val.length) {
          const sStep = this.step(ctx, n, 'sink', `assignment to ${full || prop}`);
          sStep.arg = { start: n.right.start, end: n.right.end, index: 0 };
          this.checkSink(ctx, s.category, val, sStep, full || prop);
        }
      }
      // prototype pollution: obj[key] = value with tainted key
      if (left.node.computed) {
        const keyVal = this.evalExpr(ctx, left.get('property'), state);
        const objVal = left.get('object').isMemberExpression() && left.node.object.computed ? this.evalExpr(ctx, left.get('object.property'), state) : [];
        if (keyVal.length && (val.length || objVal.length)) {
          const sStep = this.step(ctx, n, 'sink', 'dynamic property write with attacker-controlled key');
          sStep.arg = { start: left.node.property.start, end: left.node.property.end, index: 0 };
          this.checkSink(ctx, 'proto', union(objVal, keyVal), sStep, 'obj[key] = value');
        }
      }
      // weak update of the base object
      let base = left.node; while (base.type === 'MemberExpression') base = base.object;
      if (base.type === 'Identifier' && val.length) {
        const bp = left.get('object'); const key = this.bindingKey(bp, base.name);
        state.set(key, union(state.get(key), extend(val, this.step(ctx, n, 'assign', `stored into ${this.text(ctx.file, left.node, 50)}`))));
      }
      return val;
    }
    if (left.isObjectPattern() || left.isArrayPattern()) this.bindPattern(ctx, left, val, state, 'assign', true);
    return val;
  }

  evalJSX(ctx, ep, state) {
    const visit = (p) => {
      if (p.isJSXElement()) {
        p.get('openingElement.attributes').forEach((a) => {
          if (!a.isJSXAttribute() || !a.node.value) return;
          if (a.node.value.type !== 'JSXExpressionContainer') return;
          const v = this.evalExpr(ctx, a.get('value.expression'), state);
          if (a.node.name.name === 'dangerouslySetInnerHTML' && v.length) {
            const sStep = this.step(ctx, a.node, 'sink', 'dangerouslySetInnerHTML');
            sStep.arg = { start: a.node.value.expression.start, end: a.node.value.expression.end, index: 0 };
            this.checkSink(ctx, 'xss', v, sStep, 'dangerouslySetInnerHTML');
          }
        });
        p.get('children').forEach(visit);
      } else if (p.isJSXFragment()) p.get('children').forEach(visit);
      else if (p.isJSXExpressionContainer()) this.evalExpr(ctx, p.get('expression'), state); // children are auto-escaped
    };
    visit(ep);
  }

  matchList(list, text) { return list.some((x) => x === text); }

  findSanitizer(callee) {
    if (!this.opts.sanitizers || !callee) return null;
    for (const s of this.sanitizers) if (s.callee.includes(callee)) return s;
    return null;
  }

  evalCall(ctx, ep, state) {
    const n = ep.node;
    const calleePath = ep.get('callee');
    const isNew = n.type === 'NewExpression';
    let callee = this.calleeText(ctx, calleePath);
    if (isNew && callee === 'Function') callee = 'new Function';
    const method = calleePath.isMemberExpression() && !calleePath.node.computed ? calleePath.node.property.name : null;
    const objectText = calleePath.isMemberExpression() ? (this.chain(calleePath.node.object)?.join('.') || '') : '';

    if (callee === 'require' || n.callee.type === 'Import') return [];

    // request accessor sources: req.get('x'), req.header('x'), req.param('x')
    if (method && ['get', 'header', 'param', 'cookie'].includes(method) && /^(req|request)$/.test(objectText)) {
      const name = n.arguments[0]?.type === 'StringLiteral' ? n.arguments[0].value : '?';
      const field = method === 'param' ? 'query' : 'headers';
      return this.sourceFlow(ctx, n, { label: `req.${field}`, field, path: [name] });
    }

    const receiver = calleePath.isMemberExpression() ? this.evalExpr(ctx, calleePath.get('object'), state) : [];
    const argPaths = ep.get('arguments');
    const args = argPaths.map((a) => (isFnNode(a.node) ? [] : this.evalExpr(ctx, a, state)));

    // Route registration: app.get('/path', handler...)
    let route = null;
    if (method && ROUTE_METHODS.has(method) && n.arguments[0]?.type === 'StringLiteral' && n.arguments[0].value.startsWith('/')) {
      route = { method: method === 'del' ? 'delete' : method, path: n.arguments[0].value, file: ctx.file, line: n.loc.start.line };
      argPaths.forEach((a) => {
        const fnRef = isFnNode(a.node) ? { path: a, file: ctx.file } : (a.isIdentifier() || a.isMemberExpression() ? this.resolveFunction(ctx, a) : null);
        if (fnRef) this.routes.set(this.fnKey(fnRef.file, fnRef.path.node), route);
      });
    }

    // ---- sinks ----
    for (const s of this.sinks) {
      const hit = (s.callee && callee && this.matchList(s.callee, callee)) ||
        (s.method && method && s.method.includes(method) && (!s.objectHint || s.objectHint.test(objectText)));
      if (!hit) continue;
      if (s.minArgs && n.arguments.length < s.minArgs) continue;
      if (s.stringOnlyFor && s.stringOnlyFor.includes(callee) && isFnNode(n.arguments[0])) continue;
      const idxs = s.lastArg ? [n.arguments.length - 1] : s.args;
      for (const i of idxs) {
        if (!args[i]?.length) continue;
        let flows = args[i];
        if (s.category === 'nosqli') flows = flows.filter((f) => f.typeHint !== 'string' && f.origin.kind !== 'source' || (f.origin.kind === 'source' && f.typeHint !== 'string' && ['body', 'query'].includes(f.origin.field)));
        if (s.category === 'sqli' && i === 0 && n.arguments[1] && n.arguments[0]?.type === 'StringLiteral') continue;
        if (!flows.length) continue;
        const sStep = this.step(ctx, n, 'sink', `${callee || method}() argument #${i}`);
        sStep.arg = { start: n.arguments[i].start, end: n.arguments[i].end, index: i };
        this.checkSink(ctx, s.category, flows, sStep, callee || `${objectText}.${method}`);
      }
    }

    // ---- user-defined functions (interprocedural) ----
    const target = this.opts.interprocedural ? this.resolveFunction(ctx, calleePath) : null;
    if (!target) {
    // ---- sanitizers ----
      const san = this.findSanitizer(callee) || (method && this.findSanitizer(method) && !calleePath.isMemberExpression() ? this.findSanitizer(method) : null);
      if (san) {
        const v = union(receiver, ...args);
        this.inlineCallbacks(ctx, argPaths, state, receiver, method);
        return extend(v, this.step(ctx, n, 'sanitizer', `sanitized by ${callee} for ${san.categories.join(', ')}`), { sanitize: san.categories, typeHint: 'string' });
      }
    }
    if (target) {
      const summary = this.summarize(target.path, target.file);
      this.stats.summariesApplied++;
      const callStep = this.step(ctx, n, 'call', `call to ${summary.name}() in ${target.file}`);
      // param -> sink effects inside callee
      for (const eff of summary.sinkEffects) {
        const a = args[eff.index] || [];
        for (const f of a) {
          if (isSanitizedFor(f, eff.category)) continue;
          const combined = mkFlow(f.origin, [...f.steps, callStep, ...eff.steps.slice(1)], { sanitized: f.sanitized, assumptions: [...f.assumptions, ...eff.assumptions] });
          this.emitOrLift(ctx, eff.category, combined, eff.sinkStep, eff.sinkName);
        }
      }
      // param/source -> return
      let result = [];
      for (const rf of summary.returns) {
        if (rf.origin.kind === 'param') {
          for (const af of args[rf.origin.index] || []) {
            result = union(result, [mkFlow(af.origin, [...af.steps, callStep, ...rf.steps.slice(1)], { sanitized: [...new Set([...af.sanitized, ...rf.sanitized])], assumptions: [...af.assumptions, ...rf.assumptions], typeHint: rf.typeHint || af.typeHint, refinable: false })]);
          }
        } else {
          result = union(result, [mkFlow(rf.origin, [...rf.steps, callStep], { sanitized: rf.sanitized, assumptions: rf.assumptions, refinable: false })]);
        }
      }
      this.inlineCallbacks(ctx, argPaths, state, receiver, method, route);
      return result;
    }

    this.inlineCallbacks(ctx, argPaths, state, receiver, method, route);

    // ---- known propagators ----
    if ((method && PROPAGATORS.has(method)) || (callee && PROPAGATORS.has(callee)) || callee === 'URL' || callee === 'String') {
      const v = union(receiver, ...args);
      const isStr = (method && STRING_PROPAGATORS.has(method)) || callee === 'String';
      return extend(v, this.step(ctx, n, 'propagate', `passes through ${callee || method}()`), isStr ? { typeHint: 'string' } : {});
    }

    // sink calls return fresh data
    if (callee && this.sinks.some((s) => s.callee?.includes(callee))) return [];

    // ---- unknown calls ----
    const v = union(receiver, ...args);
    if (v.length && callee) {
      this.stats.unknownCalls++;
      const u = this.unresolvedCalls.get(callee) || { callee, count: 0, sites: [] };
      u.count++; if (u.sites.length < 3) u.sites.push({ file: ctx.file, line: n.loc.start.line, code: this.text(ctx.file, n, 80) });
      this.unresolvedCalls.set(callee, u);
    }
    if (this.opts.unknownCallPolicy === 'drop') return [];
    return v.length ? extend(v, this.step(ctx, n, 'unknown-call', `assumed to propagate through unresolved ${callee || method || 'call'}()`), { assume: `unresolved call ${callee || method}() assumed to propagate taint` }) : [];
  }

  /** Analyze function arguments (callbacks) inline with closure state. */
  inlineCallbacks(ctx, argPaths, state, receiver, method, route = null) {
    argPaths.forEach((a) => {
      if (!isFnNode(a.node)) return;
      const key = this.fnKey(ctx.file, a.node);
      this.inlineAnalyzed.add(key);
      const child = new State(state);
      const ictx = { ...ctx, fnKey: key, summary: ctx.summary, fnPath: a, inline: true };
      const params = a.get('params');
      if (method && (ITER_METHODS.has(method) || method === 'then') && params[0] && receiver.length) {
        this.bindPattern(ictx, params[0], extend(receiver, this.step(ctx, a.node, 'propagate', `callback parameter of .${method}()`)), child, 'assign', true);
      }
      if (method === 'reduce' && params[1] && receiver.length) this.bindPattern(ictx, params[1], receiver, child, 'assign', true);
      this.stats.functionsAnalyzed++;
      // inline callbacks don't contribute returns to the enclosing summary
      const saved = ictx.summary; ictx.summary = saved ? { ...saved, returns: [] } : null;
      if (ictx.summary) { ictx.summary.sinkEffects = saved.sinkEffects; }
      this.analyzeBody(ictx, a, child);
    });
  }

  // ---------- findings ----------
  checkSink(ctx, category, val, sinkStep, sinkName) {
    for (const f of val) {
      if (isSanitizedFor(f, category)) {
        const k = `${category}:${sinkStep.file}:${sinkStep.start}:${f.origin.label || 'param'}`;
        if (!this.suppressed.has(k)) this.suppressed.set(k, { category, file: sinkStep.file, line: sinkStep.line, sink: sinkName, reason: f.steps.filter((s) => s.kind === 'sanitizer').map((s) => s.detail).join('; ') || 'sanitized' });
        continue;
      }
      this.emitOrLift(ctx, category, f, sinkStep, sinkName);
    }
  }

  emitOrLift(ctx, category, flow, sinkStep, sinkName) {
    if (flow.origin.kind === 'param') {
      if (ctx.summary) {
        const k = `${category}:${flow.origin.index}:${sinkStep.file}:${sinkStep.start}`;
        if (!ctx.summary.sinkEffects.some((e) => e.k === k)) ctx.summary.sinkEffects.push({ k, index: flow.origin.index, category, steps: flow.steps, sinkStep, sinkName, assumptions: flow.assumptions });
      }
      return;
    }
    const trace = [...flow.steps, sinkStep];
    const key = `${category}|${sinkStep.file}|${sinkStep.start}|${flow.origin.label}`;
    if (this.findings.has(key)) return;
    const cat = CATEGORIES[category];
    const id = crypto.createHash('sha1').update(key).digest('hex').slice(0, 12);
    this.findings.set(key, {
      id,
      category,
      categoryName: cat.name,
      cwe: cat.cwe,
      severity: cat.severity,
      file: sinkStep.file,
      line: sinkStep.line,
      column: sinkStep.column,
      sink: sinkName,
      sinkCode: sinkStep.code,
      source: { label: flow.origin.label, field: flow.origin.field, path: flow.origin.path || [], file: flow.origin.step.file, line: flow.origin.step.line, code: flow.origin.step.code },
      entryFn: flow.origin.fn,
      trace,
      interprocedural: trace.some((s) => s.kind === 'call'),
      crossFile: new Set(trace.map((s) => s.file)).size > 1,
      assumptions: [...new Set(flow.assumptions)],
      sanitizedFor: flow.sanitized,
      fix: cat.fix,
    });
  }

  // ---------- driver ----------
  run() {
    const t0 = Date.now();
    for (const [file, p] of this.project.parsed) {
      if (!p.root) continue;
      const ctx = { file, fnKey: `${file}:<module>`, summary: null };
      const state = new State();
      this.stats.functionsAnalyzed++;
      this.analyzeBlock(ctx, p.root.get('body'), state);
    }
    // analyze every remaining function (exported handlers, class methods, uncalled helpers)
    for (const [file, p] of this.project.parsed) {
      if (!p.root) continue;
      const fns = [];
      p.root.traverse({ Function(fp) { fns.push(fp); } });
      for (const fp of fns) {
        const key = this.fnKey(file, fp.node);
        if (this.inlineAnalyzed.has(key) || this.summaries.has(key)) continue;
        if (this.isInsideInlined(file, fp)) continue;
        this.summarize(fp, file);
      }
    }
    const findings = [...this.findings.values()].map((f) => ({ ...f, route: this.routes.get(f.entryFn) || null }));
    findings.sort((a, b) => (a.file.localeCompare(b.file)) || a.line - b.line || a.category.localeCompare(b.category));
    return {
      findings,
      suppressed: [...this.suppressed.values()],
      unresolvedCalls: [...this.unresolvedCalls.values()].sort((a, b) => b.count - a.count),
      routes: [...new Map([...this.routes.values()].map((r) => [`${r.method} ${r.path} ${r.file}`, r])).values()],
      stats: { ...this.stats, durationMs: Date.now() - t0 },
    };
  }

  isInsideInlined(file, fp) {
    let p = fp.parentPath;
    while (p) {
      if (isFnNode(p.node) && (this.inlineAnalyzed.has(this.fnKey(file, p.node)) || this.summaries.has(this.fnKey(file, p.node)))) return true;
      p = p.parentPath;
    }
    return false;
  }
}

/** Convenience: analyze a { relPath: code } map. */
export function analyzeFiles(files, options = {}) {
  const project = buildProject(files);
  const engine = new TaintEngine(project, options);
  const result = engine.run();
  return { project, ...result, coverage: project.coverage };
}
