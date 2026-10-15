/**
 * Optional LLM client. Disabled unless OPENAI_API_KEY (or ANTHROPIC_API_KEY) is
 * present. The pipeline is fully functional and deterministic without it; the
 * LLM only ever (a) rephrases already-verified claims, or (b) proposes spec
 * candidates that are then verified. It is never a source of truth.
 */
const OPENAI_URL = 'https://api.openai.com/v1/chat/completions';

export function createLLM(env = process.env) {
  const key = env.OPENAI_API_KEY;
  const model = env.EVITAINT_LLM_MODEL || 'gpt-4o-mini';
  const enabled = Boolean(key);

  async function chat(system, user, { json = false } = {}) {
    const res = await fetch(OPENAI_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({ model, temperature: 0, messages: [{ role: 'system', content: system }, { role: 'user', content: user }], ...(json ? { response_format: { type: 'json_object' } } : {}) }),
    });
    if (!res.ok) throw new Error(`LLM HTTP ${res.status}`);
    const data = await res.json();
    return data.choices?.[0]?.message?.content ?? '';
  }

  return {
    enabled,
    model,
    async complete({ system, user }) { return chat(system, user); },
    async classifyCalls(names) {
      const out = await chat(
        'Classify each JavaScript call name as a security "sink", "sanitizer", or "none". For a sink, give a category from: sqli,nosqli,cmdi,codei,path,xss,ssrf,redirect,proto. Respond as JSON {"calls":[{"name","role","category"}]}.',
        JSON.stringify({ names }), { json: true },
      );
      try { return JSON.parse(out).calls || []; } catch { return []; }
    },
  };
}
