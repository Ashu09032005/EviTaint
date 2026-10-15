/**
 * Default taint specifications for JS/TS web applications.
 *
 * Every category has a single canonical id. Severity, CWE and fix advice are
 * looked up by that id only, so the metadata mismatch from the original
 * prototype ("SQL Injection" vs "SQLInjection") cannot happen again.
 */

export const CATEGORIES = {
  sqli: {
    id: 'sqli', name: 'SQL Injection', cwe: 'CWE-89', severity: 'critical',
    fix: 'Use parameterized queries (placeholders + values array) or a query builder; never interpolate request data into SQL text.',
  },
  nosqli: {
    id: 'nosqli', name: 'NoSQL Injection', cwe: 'CWE-943', severity: 'high',
    fix: 'Cast request values to primitives (String(), Number()) or strip operator keys (mongo-sanitize) before using them in query objects.',
  },
  cmdi: {
    id: 'cmdi', name: 'Command Injection', cwe: 'CWE-78', severity: 'critical',
    fix: 'Avoid the shell: use execFile/spawn with an argument array and an allowlist of permitted values.',
  },
  codei: {
    id: 'codei', name: 'Code Injection', cwe: 'CWE-94', severity: 'critical',
    fix: 'Never pass request data to eval/Function/vm; parse data with JSON.parse or use a lookup table.',
  },
  path: {
    id: 'path', name: 'Path Traversal', cwe: 'CWE-22', severity: 'high',
    fix: 'Resolve the path against a fixed base directory and reject results outside it, or reduce the input with path.basename().',
  },
  xss: {
    id: 'xss', name: 'Cross-Site Scripting', cwe: 'CWE-79', severity: 'high',
    fix: 'HTML-encode untrusted data (escape-html) or render via a templating engine with auto-escaping; use textContent instead of innerHTML.',
  },
  ssrf: {
    id: 'ssrf', name: 'Server-Side Request Forgery', cwe: 'CWE-918', severity: 'high',
    fix: 'Validate outbound URLs against an allowlist of hosts and block internal address ranges.',
  },
  redirect: {
    id: 'redirect', name: 'Open Redirect', cwe: 'CWE-601', severity: 'medium',
    fix: 'Redirect only to relative paths or to an allowlisted set of destinations.',
  },
  proto: {
    id: 'proto', name: 'Prototype Pollution', cwe: 'CWE-1321', severity: 'high',
    fix: 'Reject the keys __proto__, constructor and prototype, or use Object.create(null)/Map for user-keyed data.',
  },
  secret: {
    id: 'secret', name: 'Hardcoded Secret', cwe: 'CWE-798', severity: 'high',
    fix: 'Move the secret to environment variables or a secret manager and rotate the exposed value.',
  },
};

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Sources: member-expression prefixes considered attacker controlled.
 * `objects` are identifier names for the request object; `props` the fields.
 */
export const SOURCES = {
  requestObjects: ['req', 'request', 'ctx.request', 'ctx'],
  requestProps: ['body', 'query', 'params', 'headers', 'cookies', 'files', 'file', 'path', 'url', 'originalUrl', 'hostname', 'ip'],
  // Browser-side sources
  browser: ['location.search', 'location.hash', 'location.href', 'document.cookie', 'document.URL', 'document.referrer', 'window.location.search', 'window.location.hash', 'window.name'],
  // CLI input is attacker controlled for CLIs; env vars are not (deployment-controlled).
  process: ['process.argv'],
};

/**
 * Call sinks. `callee` is matched against the textual callee (e.g. "db.query"),
 * using either the full text, or the trailing method name when `method` is set.
 * `args` lists which argument indexes are dangerous.
 */
export const CALL_SINKS = [
  // SQL
  { category: 'sqli', method: ['query', 'execute', 'raw', 'whereRaw', 'orderByRaw', 'havingRaw', '$queryRawUnsafe', '$executeRawUnsafe', 'exec'], objectHint: /(db|conn|connection|pool|client|knex|sequelize|mysql|pg|sql|database|prisma|sqlite|trx|tx)/i, args: [0] },
  // NoSQL (operator injection when an object from the request is passed directly)
  { category: 'nosqli', method: ['find', 'findOne', 'findOneAndUpdate', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'countDocuments', 'where'], objectHint: /(collection|model|users?|db\.|mongo|User|Post|Order|Product|Account)/, args: [0], requireObjectValue: true },
  // Command injection
  { category: 'cmdi', callee: ['exec', 'execSync', 'child_process.exec', 'child_process.execSync', 'cp.exec', 'cp.execSync', 'shell.exec'], args: [0] },
  { category: 'cmdi', callee: ['spawn', 'spawnSync', 'child_process.spawn', 'cp.spawn', 'execFile', 'execFileSync', 'child_process.execFile'], args: [0] },
  // Code injection
  { category: 'codei', callee: ['eval', 'Function', 'vm.runInNewContext', 'vm.runInThisContext', 'vm.runInContext', 'setTimeout', 'setInterval', 'new Function'], args: [0], stringOnlyFor: ['setTimeout', 'setInterval'] },
  // Path traversal
  { category: 'path', callee: ['fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync', 'fs.appendFile', 'fs.appendFileSync', 'fs.createReadStream', 'fs.createWriteStream', 'fs.unlink', 'fs.unlinkSync', 'fs.rm', 'fs.rmSync', 'fs.readdir', 'fs.readdirSync', 'fs.promises.readFile', 'fs.promises.writeFile', 'fsp.readFile', 'fsp.writeFile', 'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream'], args: [0] },
  { category: 'path', method: ['sendFile', 'download'], objectHint: /^(res|response|reply)$/, args: [0] },
  // XSS (server responses)
  { category: 'xss', method: ['send', 'write', 'end'], objectHint: /^(res|response|reply)$/, args: [0] },
  { category: 'xss', callee: ['document.write', 'document.writeln'], args: [0] },
  { category: 'xss', method: ['insertAdjacentHTML'], args: [1] },
  // SSRF
  { category: 'ssrf', callee: ['fetch', 'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.request', 'http.get', 'https.get', 'http.request', 'https.request', 'got', 'got.get', 'request', 'request.get', 'needle.get', 'superagent.get'], args: [0] },
  // Open redirect
  { category: 'redirect', method: ['redirect'], objectHint: /^(res|response|reply|ctx)$/, args: [0], lastArg: true },
  // Prototype pollution via deep merge helpers
  { category: 'proto', callee: ['_.merge', 'lodash.merge', '_.defaultsDeep', 'merge', 'deepmerge', 'extend', '$.extend', '_.set', 'lodash.set', 'set'], args: [1, 2], requireObjectValue: false, minArgs: 2 },
];

/** Assignment sinks: `target.prop = value`. */
export const ASSIGN_SINKS = [
  { category: 'xss', prop: ['innerHTML', 'outerHTML'] },
  { category: 'redirect', member: ['location.href', 'window.location', 'window.location.href', 'document.location', 'location'] },
];

/** JSX attribute sinks. */
export const JSX_SINKS = [{ category: 'xss', attr: 'dangerouslySetInnerHTML' }];

/**
 * Sanitizers: call names that neutralize taint for the listed categories.
 * '*' means the result is safe for every category (type coercion).
 */
export const SANITIZERS = [
  { callee: ['Number', 'parseInt', 'parseFloat', 'Boolean', 'Math.floor', 'Math.round', 'Math.abs', 'isNaN', 'Number.parseInt', 'Number.isInteger'], categories: ['*'] },
  { callee: ['escapeHtml', 'escape-html', 'escape', 'he.encode', 'he.escape', 'validator.escape', 'DOMPurify.sanitize', 'sanitizeHtml', 'xss', 'filterXSS', 'encodeHTML', '_.escape', 'lodash.escape', 'htmlEscape'], categories: ['xss'] },
  { callee: ['encodeURIComponent'], categories: ['xss', 'redirect', 'path', 'cmdi'] },
  { callee: ['path.basename', 'basename'], categories: ['path'] },
  { callee: ['sqlstring.escape', 'SqlString.escape', 'mysql.escape', 'connection.escape', 'pool.escape', 'db.escape', 'pgFormat', 'format.literal', 'escapeLiteral', 'client.escapeLiteral'], categories: ['sqli'] },
  { callee: ['shellQuote.quote', 'quote', 'shellescape', 'shellEscape'], categories: ['cmdi'] },
  { callee: ['mongoSanitize', 'mongoSanitize.sanitize', 'String'], categories: ['nosqli'] },
  { callee: ['guards.safeUrl', 'safeUrl', 'isAllowedUrl', 'guards.allowlistUrl'], categories: ['ssrf'] },
  { callee: ['guards.safeRedirect', 'safeRedirect'], categories: ['redirect'] },
  { callee: ['guards.safeKey', 'safeKey'], categories: ['proto'] },
  { callee: ['JSON.stringify'], categories: ['codei', 'nosqli'] },
];

/** Calls that pass taint from receiver/arguments to their result. */
export const PROPAGATORS = new Set([
  'trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'concat', 'replace', 'replaceAll', 'slice', 'substring', 'substr',
  'split', 'join', 'padStart', 'padEnd', 'toString', 'valueOf', 'normalize', 'at', 'map', 'filter', 'flat', 'reduce', 'find',
  'JSON.parse', 'decodeURIComponent', 'decodeURI', 'Buffer.from', 'path.join', 'path.resolve', 'path.normalize', 'join', 'resolve',
  'Object.assign', 'Object.values', 'Object.entries', 'Array.from', 'url.parse', 'querystring.parse', 'atob', 'btoa', 'format', 'util.format',
]);

/** Category-specific sanitizer used when synthesizing counterfactual patches. */
export const PATCH_SANITIZER = {
  sqli: { wrap: (e) => `require('sqlstring').escape(${e})`, name: 'sqlstring.escape' },
  nosqli: { wrap: (e) => `String(${e})`, name: 'String' },
  cmdi: { wrap: (e) => `require('shell-quote').quote([${e}])`, name: 'shell-quote quote' },
  codei: { wrap: (e) => `JSON.stringify(${e})`, name: 'JSON.stringify' },
  path: { wrap: (e) => `require('path').basename(${e})`, name: 'path.basename' },
  xss: { wrap: (e) => `require('escape-html')(${e})`, name: 'escape-html' },
  ssrf: { wrap: (e) => `require('./evitaint-guards').safeUrl(${e})`, name: 'guards.safeUrl' },
  redirect: { wrap: (e) => `require('./evitaint-guards').safeRedirect(${e})`, name: 'guards.safeRedirect' },
  proto: { wrap: (e) => `require('./evitaint-guards').safeKey(${e})`, name: 'guards.safeKey' },
};

// Calls of the form require('x')(...) / require('x').y(...) are normalized to
// "x" / "x.y" by the engine; register package-name aliases for sanitizers here.
export const PACKAGE_ALIASES = {
  'escape-html': 'escapeHtml',
  'sqlstring': 'sqlstring',
  'shell-quote': 'shellQuote',
  'path': 'path',
  'fs': 'fs',
  'fs/promises': 'fsp',
  'child_process': 'child_process',
  'node:fs': 'fs',
  'node:path': 'path',
  'node:child_process': 'child_process',
  './evitaint-guards': 'guards',
  'mongo-sanitize': 'mongoSanitize',
  'lodash': '_',
  'vm': 'vm',
  'axios': 'axios',
};
