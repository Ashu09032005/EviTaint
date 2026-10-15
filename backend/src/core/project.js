import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';
import traverseMod from '@babel/traverse';
import { PACKAGE_ALIASES } from '../specs/defaultSpecs.js';

const traverse = traverseMod.default || traverseMod;

export const SOURCE_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache', 'vendor']);
const MAX_FILE_BYTES = 1_000_000;

/** Recursively list analyzable source files (relative paths, sorted for determinism). */
export function listSourceFiles(rootDir) {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) walk(full);
      } else if (SOURCE_EXTENSIONS.includes(path.extname(entry.name)) && !entry.name.endsWith('.min.js')) {
        out.push(path.relative(rootDir, full).split(path.sep).join('/'));
      }
    }
  };
  walk(rootDir);
  return out.sort();
}

/** Load a project from disk into an in-memory map { relPath: code }. */
export function readProject(rootDir) {
  const files = {};
  const skipped = [];
  for (const rel of listSourceFiles(rootDir)) {
    const full = path.join(rootDir, rel);
    const size = fs.statSync(full).size;
    if (size > MAX_FILE_BYTES) { skipped.push({ file: rel, reason: `file larger than ${MAX_FILE_BYTES} bytes` }); continue; }
    files[rel] = fs.readFileSync(full, 'utf8');
  }
  return { files, skipped };
}

function parserPlugins(file) {
  const ext = path.extname(file);
  const plugins = ['jsx', 'classProperties', 'classPrivateProperties', 'classPrivateMethods', 'optionalChaining', 'nullishCoalescingOperator', 'objectRestSpread', 'dynamicImport', 'topLevelAwait'];
  if (ext === '.ts' || ext === '.tsx') {
    plugins.push('typescript', ['decorators', { decoratorsBeforeExport: true }]);
    if (ext === '.ts') plugins.splice(plugins.indexOf('jsx'), 1);
  } else {
    plugins.push(['decorators', { decoratorsBeforeExport: true }]);
  }
  return plugins;
}

/**
 * Parse one file. Parse problems are never silently converted into "no
 * findings": recoverable errors and fatal failures are both returned so the
 * report can show them as coverage gaps.
 */
export function parseFile(file, code) {
  try {
    const ast = parse(code, {
      sourceType: 'unambiguous',
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      plugins: parserPlugins(file),
    });
    let root = null;
    traverse(ast, { Program(p) { root = p; p.stop(); } });
    const recovered = (ast.errors || []).map((e) => ({ message: e.reasonCode || e.message, line: e.loc?.line ?? null }));
    return { file, code, ast, root, status: recovered.length ? 'partial' : 'ok', errors: recovered };
  } catch (e) {
    return { file, code, ast: null, root: null, status: 'failed', errors: [{ message: e.message, line: e.loc?.line ?? null }] };
  }
}

/** Resolve a relative import specifier to a project file. */
export function resolveModule(fromFile, spec, fileSet) {
  if (!spec.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec));
  const candidates = [base, ...SOURCE_EXTENSIONS.map((e) => base + e), ...SOURCE_EXTENSIONS.map((e) => `${base}/index${e}`)];
  // TS projects often import './x.js' that is really './x.ts'
  if (/\.js$/.test(base)) candidates.push(base.replace(/\.js$/, '.ts'), base.replace(/\.js$/, '.tsx'));
  return candidates.find((c) => fileSet.has(c)) || null;
}

const isFn = (n) => n && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression' || n.type === 'ClassMethod' || n.type === 'ObjectMethod');

function requireArg(node) {
  if (node && node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral') return node.arguments[0].value;
  if (node && node.type === 'AwaitExpression') return null;
  return null;
}

/**
 * Build per-file module facts:
 *   imports:   binding-name -> { module, imported }   (imported: 'default' | '*' | name)
 *   exports:   export-name  -> NodePath of a function (or a local identifier name)
 */
export function collectModuleFacts(parsed) {
  const imports = new Map();
  const exportsMap = new Map();
  const localFns = new Map(); // name -> function NodePath (top-level)
  if (!parsed.root) return { imports, exports: exportsMap, localFns };

  for (const stmt of parsed.root.get('body')) {
    const n = stmt.node;
    if (n.type === 'ImportDeclaration') {
      const mod = n.source.value;
      for (const s of n.specifiers) {
        if (s.type === 'ImportDefaultSpecifier') imports.set(s.local.name, { module: mod, imported: 'default' });
        else if (s.type === 'ImportNamespaceSpecifier') imports.set(s.local.name, { module: mod, imported: '*' });
        else imports.set(s.local.name, { module: mod, imported: s.imported.name || s.imported.value });
      }
    }
    if (n.type === 'VariableDeclaration') {
      stmt.get('declarations').forEach((d) => {
        const init = d.node.init;
        const req = requireArg(init) || (init?.type === 'MemberExpression' && requireArg(init.object) ? requireArg(init.object) : null);
        if (req) {
          const memberName = init.type === 'MemberExpression' && !init.computed ? init.property.name : null;
          if (d.node.id.type === 'Identifier') imports.set(d.node.id.name, { module: req, imported: memberName || '*' });
          if (d.node.id.type === 'ObjectPattern') {
            for (const p of d.node.id.properties) {
              if (p.type === 'ObjectProperty' && p.value.type === 'Identifier') imports.set(p.value.name, { module: req, imported: p.key.name || p.key.value });
            }
          }
        }
        if (d.node.id.type === 'Identifier' && isFn(init)) localFns.set(d.node.id.name, d.get('init'));
      });
    }
    if (n.type === 'FunctionDeclaration' && n.id) localFns.set(n.id.name, stmt);
    if (n.type === 'ExportNamedDeclaration') {
      const decl = stmt.get('declaration');
      if (decl.node?.type === 'FunctionDeclaration') { localFns.set(decl.node.id.name, decl); exportsMap.set(decl.node.id.name, decl); }
      if (decl.node?.type === 'VariableDeclaration') {
        decl.get('declarations').forEach((d) => {
          if (d.node.id.type === 'Identifier' && isFn(d.node.init)) { localFns.set(d.node.id.name, d.get('init')); exportsMap.set(d.node.id.name, d.get('init')); }
        });
      }
      for (const s of n.specifiers || []) exportsMap.set(s.exported.name, s.local.name);
    }
    if (n.type === 'ExportDefaultDeclaration') {
      const d = stmt.get('declaration');
      if (isFn(d.node)) exportsMap.set('default', d);
      else if (d.node.type === 'Identifier') exportsMap.set('default', d.node.name);
    }
    // CommonJS exports
    if (n.type === 'ExpressionStatement' && n.expression.type === 'AssignmentExpression') {
      const left = n.expression.left; const rightPath = stmt.get('expression.right'); const right = rightPath.node;
      const isModExports = left.type === 'MemberExpression' && left.object.type === 'Identifier' && left.object.name === 'module' && left.property.name === 'exports';
      const isExportsMember = left.type === 'MemberExpression' && ((left.object.type === 'Identifier' && left.object.name === 'exports') ||
        (left.object.type === 'MemberExpression' && left.object.object.name === 'module' && left.object.property.name === 'exports'));
      if (isModExports) {
        if (right.type === 'ObjectExpression') {
          rightPath.get('properties').forEach((p) => {
            const key = p.node.key?.name || p.node.key?.value;
            if (!key) return;
            if (p.node.type === 'ObjectMethod') exportsMap.set(key, p);
            else if (isFn(p.node.value)) exportsMap.set(key, p.get('value'));
            else if (p.node.value?.type === 'Identifier') exportsMap.set(key, p.node.value.name);
          });
        } else if (isFn(right)) exportsMap.set('default', rightPath);
        else if (right.type === 'Identifier') exportsMap.set('default', right.name);
      } else if (isExportsMember) {
        const key = left.property.name || left.property.value;
        if (isFn(right)) exportsMap.set(key, rightPath);
        else if (right.type === 'Identifier') exportsMap.set(key, right.name);
      }
    }
  }
  // Resolve exported local names to function paths
  for (const [k, v] of exportsMap) if (typeof v === 'string' && localFns.has(v)) exportsMap.set(k, localFns.get(v));
  return { imports, exports: exportsMap, localFns };
}

/** Canonical alias of an imported binding for a known package, e.g. cp -> child_process. */
export function packageAlias(imp) {
  if (!imp) return null;
  const alias = PACKAGE_ALIASES[imp.module];
  if (!alias) return null;
  if (imp.imported === '*' || imp.imported === 'default') return alias;
  return `${alias}.${imp.imported}`;
}

/** Load + parse a whole project and compute coverage. */
export function buildProject(files) {
  const fileSet = new Set(Object.keys(files));
  const parsed = new Map();
  const modules = new Map();
  for (const [file, code] of Object.entries(files)) {
    const p = parseFile(file, code);
    parsed.set(file, p);
    modules.set(file, collectModuleFacts(p));
  }
  const coverage = {
    filesDiscovered: fileSet.size,
    filesParsed: [...parsed.values()].filter((p) => p.status === 'ok').length,
    filesPartiallyParsed: [...parsed.values()].filter((p) => p.status === 'partial').map((p) => ({ file: p.file, errors: p.errors })),
    filesFailed: [...parsed.values()].filter((p) => p.status === 'failed').map((p) => ({ file: p.file, errors: p.errors })),
  };
  return { files, fileSet, parsed, modules, coverage };
}
