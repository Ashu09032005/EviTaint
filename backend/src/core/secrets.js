/**
 * Hardcoded secret detection (CWE-798): provider token patterns plus
 * name/entropy rules for string literals assigned to secret-like names.
 */
import crypto from 'node:crypto';
import { CATEGORIES } from '../specs/defaultSpecs.js';

const PROVIDER_PATTERNS = [
  { name: 'AWS access key id', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/ },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { name: 'Stripe secret key', re: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'OpenAI-style API key', re: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'Connection string with password', re: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^:\s/]+:[^@\s]{3,}@/ },
];

const SECRET_NAME = /(secret|token|api[_-]?key|apikey|passw(or)?d|pwd|private[_-]?key|client[_-]?secret|auth[_-]?key|access[_-]?key|signing[_-]?key|jwt[_-]?key)/i;
const PLACEHOLDER = /^(x+|\*+|changeme|change[_-]?me|your[_-].*|<.*>|\$\{.*\}|example|test|dummy|placeholder|todo|null|undefined|password|secret|redacted|\.\.\.)$/i;

export function shannonEntropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const c of Object.values(freq)) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

function mask(v) { return v.length <= 8 ? '****' : `${v.slice(0, 4)}…${v.slice(-2)} (${v.length} chars)`; }

export function detectSecrets(project) {
  const findings = [];
  for (const [file, p] of project.parsed) {
    if (!p.root) continue;
    if (/(^|\/)(test|tests|__tests__|fixtures?)\//.test(file) || /\.(test|spec)\.[jt]sx?$/.test(file)) continue;
    p.root.traverse({
      StringLiteral(sp) { check(sp, sp.node.value); },
      TemplateLiteral(tp) { if (tp.node.expressions.length === 0) check(tp, tp.node.quasis[0].value.cooked || ''); },
    });
    function nameFor(sp) {
      const parent = sp.parent;
      if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') return parent.id.name;
      if (parent.type === 'ObjectProperty' && parent.value === sp.node) return parent.key.name || parent.key.value;
      if (parent.type === 'AssignmentExpression' && parent.left.type === 'MemberExpression') return parent.left.property.name;
      if (parent.type === 'AssignmentExpression' && parent.left.type === 'Identifier') return parent.left.name;
      if (parent.type === 'LogicalExpression' && sp.parentPath.parent.type === 'VariableDeclarator') return sp.parentPath.parent.id.name; // const KEY = process.env.KEY || 'literal'
      return null;
    }
    function check(sp, value) {
      if (!value || value.length < 8 || value.length > 4000) return;
      let rule = null;
      for (const pat of PROVIDER_PATTERNS) if (pat.re.test(value)) { rule = { kind: 'provider-pattern', name: pat.name }; break; }
      const name = nameFor(sp);
      const entropy = shannonEntropy(value);
      if (!rule && name && SECRET_NAME.test(name) && !PLACEHOLDER.test(value) && !/\s/.test(value) && entropy >= 3.0 && !/^(https?:)?\/\//.test(value)) {
        rule = { kind: 'name+entropy', name: `secret-like identifier "${name}"` };
      }
      if (!rule) return;
      const node = sp.node; const cat = CATEGORIES.secret;
      const fallback = sp.parent.type === 'LogicalExpression';
      const step = { kind: 'sink', file, line: node.loc.start.line, column: node.loc.start.column, start: node.start, end: node.end, code: (name ? `${name} = ` : '') + JSON.stringify(mask(value)), detail: `${rule.name}; entropy ${entropy.toFixed(2)} bits/char${fallback ? '; used as fallback when env var is missing' : ''}` };
      findings.push({
        id: crypto.createHash('sha1').update(`secret|${file}|${node.start}`).digest('hex').slice(0, 12),
        category: 'secret', categoryName: cat.name, cwe: cat.cwe, severity: rule.kind === 'provider-pattern' ? 'high' : 'medium',
        file, line: node.loc.start.line, column: node.loc.start.column, sink: name || 'string literal', sinkCode: step.code,
        source: { label: 'hardcoded literal', field: null, path: [], file, line: node.loc.start.line, code: step.code },
        trace: [step], interprocedural: false, crossFile: false, assumptions: [], sanitizedFor: [], fix: cat.fix,
        secretEvidence: { rule: rule.kind, ruleName: rule.name, entropy: Number(entropy.toFixed(2)), length: value.length, identifier: name },
        route: null,
      });
    }
  }
  return findings;
}
