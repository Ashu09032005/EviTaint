/**
 * Inert mocks for the dynamic reachability harness.
 *
 * SAFETY: nothing here performs a real dangerous operation. Every framework
 * and module is replaced by a stub that does nothing except RECORD the value
 * passed to a sensitive position. The harness never builds attack payloads; it
 * injects a single unique benign marker token as request input and checks
 * whether that marker reaches a sink argument unmodified. This confirms that a
 * taint flow is dynamically reachable, not that anything is exploitable.
 */

const DB_METHODS = new Set(['query', 'execute', 'raw', 'run', 'all', 'get', 'each', 'prepare', 'whereRaw', 'orderByRaw', 'havingRaw', '$queryRawUnsafe', '$executeRawUnsafe', 'unsafe']);
const NOSQL_OPS = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'countDocuments', 'where', 'findById'];
const FS_READS = new Set(['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync']);
const FS_WRITES = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'rm', 'rmSync']);

/**
 * @param {function} record  called as record(category, value, meta) whenever a
 *                           value reaches a sink of that category.
 */
export function createMocks(record) {
  const defer = (fn, ...a) => { if (typeof fn === 'function') setImmediate(() => { try { fn(...a); } catch { /* inert */ } }); };
  const lastFn = (args) => (typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null);
  const resultSet = () => Object.assign([], { rows: [], rowCount: 0, affectedRows: 0, insertId: 1, recordset: [] });

  // Generic do-nothing proxy for unknown modules.
  function stub(name = 'stub') {
    const fn = function () {};
    return new Proxy(fn, {
      get(_t, p) {
        if (p === 'then' || p === '__esModule' || typeof p === 'symbol') return undefined;
        if (p === 'toString' || p === 'valueOf' || p === 'inspect') return () => '';
        return stub(`${name}.${String(p)}`);
      },
      apply(_t, _this, args) { defer(lastFn(args), null, resultSet()); return stub(`${name}()`); },
      construct() { return stub(`new ${name}`); },
    });
  }

  // --- databases (SQL): record the query text only ---
  function dbHandle(label) {
    return new Proxy({}, {
      get(_t, p) {
        if (p === 'then' || typeof p === 'symbol') return undefined;
        if (p === 'promise') return () => dbHandle(label);
        if (DB_METHODS.has(p)) {
          return (...args) => {
            const text = typeof args[0] === 'string' ? args[0] : (args[0] && typeof args[0].sql === 'string' ? args[0].sql : null);
            if (text !== null) record('sqli', text, { method: p, parameterized: Array.isArray(args[1]) && args[1].length > 0 });
            const cb = lastFn(args);
            if (cb) { defer(cb, null, resultSet(), []); return dbHandle(label); }
            return Object.assign(Promise.resolve([resultSet(), []]), { rows: [] });
          };
        }
        return (...args) => { defer(lastFn(args), null); return dbHandle(label); };
      },
    });
  }
  const dbModule = (label) => new Proxy(function () { return dbHandle(label); }, {
    get(_t, p) { if (p === 'then' || typeof p === 'symbol') return undefined; if (p === 'default') return dbModule(label); return dbModule(label + '.x'); },
    apply() { return dbHandle(label); },
    construct() { return dbHandle(label); },
  });

  // --- mongo/mongoose: record the filter object ---
  function nosqlQuery(op, filter) {
    record('nosqli', filter, { op });
    const q = { exec: () => Promise.resolve(null), lean: () => q, sort: () => q, limit: () => q, skip: () => q, select: () => q, populate: () => q, then: (r, j) => Promise.resolve(null).then(r, j), catch: (j) => Promise.resolve(null).catch(j) };
    return q;
  }
  function model() {
    const m = function () {};
    for (const op of NOSQL_OPS) m[op] = (filter, ...rest) => { const q = nosqlQuery(op, filter); defer(lastFn(rest), null, null); return q; };
    return m;
  }

  // --- child_process: record the command/arg, never spawn anything ---
  const childProcess = {
    exec: (...a) => { record('cmdi', a[0], { api: 'exec' }); defer(lastFn(a), null, '', ''); return stub('cp'); },
    execSync: (...a) => { record('cmdi', a[0], { api: 'execSync' }); return Buffer.from(''); },
    execFile: (...a) => { record('cmdi', a[1] ?? a[0], { api: 'execFile' }); defer(lastFn(a), null, '', ''); return stub('cp'); },
    execFileSync: (...a) => { record('cmdi', a[1] ?? a[0], { api: 'execFileSync' }); return Buffer.from(''); },
    spawn: (...a) => { record('cmdi', a[1] ?? a[0], { api: 'spawn' }); return stub('cp'); },
    spawnSync: (...a) => { record('cmdi', a[1] ?? a[0], { api: 'spawnSync' }); return { stdout: Buffer.from('') }; },
    fork: () => stub('cp'),
  };

  // --- fs: record the path, read/write nothing ---
  const fsHandler = (name) => (...a) => {
    if (FS_READS.has(name) || FS_WRITES.has(name)) record('path', a[0], { api: name });
    const cb = lastFn(a);
    if (name.endsWith('Sync')) return FS_READS.has(name) ? Buffer.from('') : undefined;
    defer(cb, null, Buffer.from(''));
    return stub('fs');
  };
  const fsProxy = new Proxy({}, {
    get(_t, p) {
      if (p === 'then' || typeof p === 'symbol') return undefined;
      if (p === 'promises') return new Proxy({}, { get: (_t2, q) => (...a) => { if (FS_READS.has(q) || FS_WRITES.has(q)) record('path', a[0], { api: `promises.${String(q)}` }); return Promise.resolve(Buffer.from('')); } });
      if (p === 'constants') return {};
      if (p === 'existsSync') return () => true;
      if (p === 'statSync') return () => ({ isFile: () => true, isDirectory: () => false, size: 0 });
      if (p === 'createReadStream' || p === 'createWriteStream') return (...a) => { record('path', a[0], { api: String(p) }); return stub('stream'); };
      return fsHandler(String(p));
    },
  });

  // --- code evaluation: record the argument, never evaluate it ---
  const codeSink = (api) => (v) => { record('codei', v, { api }); return undefined; };

  // --- outbound HTTP (SSRF): record the URL, make no request ---
  const httpClient = (api) => (...a) => { record('ssrf', a[0], { api }); defer(lastFn(a), null, { statusCode: 200, on: () => {} }); return Object.assign(Promise.resolve({ data: '', status: 200 }), { on: () => httpClient(api), end: () => {} }); };

  return { stub, dbModule, dbHandle, model, childProcess, fsProxy, codeSink, httpClient, nosqlQuery, resultSet };
}
