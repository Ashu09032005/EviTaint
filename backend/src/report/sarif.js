/** Export an EviTaint report to SARIF 2.1.0 for CI / code-scanning tools. */
export function toSARIF(report) {
  const rules = new Map();
  const results = report.findings.map((f) => {
    if (!rules.has(f.category)) rules.set(f.category, {
      id: f.category, name: f.categoryName,
      shortDescription: { text: f.categoryName },
      properties: { cwe: f.cwe, 'security-severity': ({ critical: '9.5', high: '8.0', medium: '5.0', low: '3.0', info: '1.0' }[f.severity]) },
    });
    const expl = report.explanations[f.id];
    return {
      ruleId: f.category,
      level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
      message: { text: expl ? expl.prose : f.categoryName },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: (f.column || 0) + 1 } } }],
      codeFlows: f.trace ? [{ threadFlows: [{ locations: f.trace.map((s) => ({ location: { physicalLocation: { artifactLocation: { uri: s.file }, region: { startLine: s.line } }, message: { text: `${s.kind}: ${s.detail}` } } })) }] }] : undefined,
      properties: { confidence: f.confidence?.calibrated, faithfulness: f.faithfulness, confirmation: f.confirmation, counterfactual: f.counterfactual, cwe: f.cwe },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'EviTaint', version: report.meta.version, informationUri: 'https://example.org/evitaint', rules: [...rules.values()] } },
      results,
    }],
  };
}
