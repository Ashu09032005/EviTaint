/**
 * Dynamic reachability harness.
 *
 * Confirms a static finding by executing ONLY the relevant route handler inside
 * a forked worker, under fully inert mocks (see mocks.js). The request input
 * named by the finding's source is set to a unique benign marker token. If the
 * marker reaches the matching sink unmodified, the finding is dynamically
 * confirmed as reachable; if it reaches the sink in neutralized form, it is
 * recorded as sanitized; if it never arrives, the flow is not reachable at
 * runtime. No attack payloads are constructed or executed.
 */
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const WORKER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'worker.js');
const TIMEOUT_MS = 4000;

/**
 * @param {object} finding   a taint finding (needs source.field, source.path, category, route)
 * @param {object} files     { relPath: code } of the project
 * @returns {Promise<object>} confirmation record
 */
export function confirmFinding(finding, files, opts = {}) {
  if (finding.category === 'secret') {
    return Promise.resolve({ status: 'not-applicable', reason: 'static-only category (hardcoded secret)' });
  }
  if (!finding.route) {
    return Promise.resolve({ status: 'inconclusive', reason: 'no route entry point resolved for this finding; handler cannot be driven in isolation' });
  }
  return new Promise((resolve) => {
    const child = fork(WORKER, [], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], execArgv: [] });
    let settled = false;
    const done = (r) => { if (settled) return; settled = true; clearTimeout(timer); try { child.kill('SIGKILL'); } catch {} resolve(r); };
    const timer = setTimeout(() => done({ status: 'inconclusive', reason: `handler did not settle within ${TIMEOUT_MS}ms (possible loop or external wait)` }), TIMEOUT_MS);
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d.toString().slice(0, 2000); });
    child.on('message', (m) => done(m));
    child.on('error', (e) => done({ status: 'error', reason: e.message }));
    child.on('exit', (code) => { if (!settled) done({ status: 'error', reason: `worker exited (code ${code})`, stderr: stderr.slice(0, 500) }); });
    child.send({ files, finding, timeoutMs: TIMEOUT_MS - 500 });
  });
}

export async function confirmAll(findings, files, opts = {}) {
  const out = [];
  for (const f of findings) {
    // eslint-disable-next-line no-await-in-loop
    out.push({ id: f.id, ...(await confirmFinding(f, files, opts)) });
  }
  return out;
}
