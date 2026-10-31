// A cross-reference of each detection category to OWASP (LLM Top 10 2025 and Agentic Top 10), MITRE ATLAS and NIST AI RMF labels.
// LAB-ILLUSTRATIVE: the deck says Ping tags every detection and denial from a versioned catalogue held in code; the lab does not have that
// catalogue. These labels are written by the lab from the public framework names as it recalls them. Check them against the published
// frameworks before relying on any of them; they are not Ping's mapping.
export const COMPLIANCE_NOTE = 'Lab-illustrative labels, not Ping\'s versioned catalogue. IDs are as the lab recalls them from the public frameworks: verify before use.';
export const FRAMEWORKS = [
  { id: 'owaspLlm', label: 'OWASP LLM Top 10 (2025)' },
  { id: 'asi', label: 'OWASP Agentic AI Top 10 (ASI)' },
  { id: 'atlas', label: 'MITRE ATLAS' },
  { id: 'nist', label: 'NIST AI RMF' },
];
export const CATEGORY_MAP = {
  prompt_injection: { owaspLlm: 'LLM01 Prompt Injection', asi: 'ASI01', atlas: 'AML.T0051 LLM Prompt Injection', nist: 'MEASURE 2.7' },
  jailbreak: { owaspLlm: 'LLM01 Prompt Injection', asi: 'ASI01', atlas: 'AML.T0054 LLM Jailbreak', nist: 'MEASURE 2.7' },
  hidden_instructions: { owaspLlm: 'LLM01 Prompt Injection', asi: 'ASI01', atlas: 'AML.T0051 LLM Prompt Injection', nist: 'MEASURE 2.7' },
  indirect_injection: { owaspLlm: 'LLM01 Prompt Injection', asi: 'ASI01', atlas: 'AML.T0051 LLM Prompt Injection', nist: 'MEASURE 2.7' },
  data_exfiltration: { owaspLlm: 'LLM02 Sensitive Information Disclosure', asi: 'ASI09', atlas: 'AML.T0057 LLM Data Leakage', nist: 'MEASURE 2.10' },
  pii: { owaspLlm: 'LLM02 Sensitive Information Disclosure', asi: 'ASI09', atlas: 'AML.T0057 LLM Data Leakage', nist: 'MEASURE 2.10' },
  secrets: { owaspLlm: 'LLM02 Sensitive Information Disclosure', asi: 'ASI03', atlas: 'AML.T0057 LLM Data Leakage', nist: 'MEASURE 2.10' },
  tool_abuse: { owaspLlm: 'LLM06 Excessive Agency', asi: 'ASI02', atlas: 'AML.T0053 LLM Plugin Compromise', nist: 'MANAGE 2.3' },
  schema_violation: { owaspLlm: 'LLM05 Improper Output Handling', asi: 'ASI02', atlas: 'AML.T0053 LLM Plugin Compromise', nist: 'MEASURE 2.7' },
  malicious_content: { owaspLlm: 'LLM05 Improper Output Handling', asi: 'ASI05', atlas: 'AML.T0053 LLM Plugin Compromise', nist: 'MEASURE 2.7' },
  tool_poisoning: { owaspLlm: 'LLM03 Supply Chain', asi: 'ASI04', atlas: 'AML.T0053 LLM Plugin Compromise', nist: 'MAP 4.1' },
  memory_poisoning: { owaspLlm: 'LLM04 Data and Model Poisoning', asi: 'ASI06', atlas: 'AML.T0020 Poison Training Data (family)', nist: 'MEASURE 2.7' },
  inter_agent_abuse: { owaspLlm: 'LLM06 Excessive Agency', asi: 'ASI07', atlas: 'AML.T0053 LLM Plugin Compromise', nist: 'MANAGE 2.3' },
};
export const mappingFor = (category) => (typeof category === 'string' && Object.hasOwn(CATEGORY_MAP, category) ? CATEGORY_MAP[category] : null);

// Counts of findings (events with a category) per framework label.
export function complianceSummary(events) {
  const out = Object.fromEntries(FRAMEWORKS.map((f) => [f.id, {}]));
  for (const e of events) {
    const m = mappingFor(e.category); if (!m) continue;
    for (const f of FRAMEWORKS) out[f.id][m[f.id]] = (out[f.id][m[f.id]] || 0) + 1;
  }
  return out;
}
