// The detection categories, the roles content can arrive in, the surfaces, and the default thresholds. Each category says where its name comes
// from: "console swagger key" (a key of modelAIGuardConfig.Categories, 2026-10-31, schema only), "deck name, no swagger key" (the deck names
// it, the schema has no such key) or "lab-invented". The default thresholds and the scores are LAB-INVENTED.
export const CATEGORIES = [
  { id: 'prompt_injection', label: 'Prompt injection', source: 'console swagger key' },
  { id: 'jailbreak', label: 'Jailbreak', source: 'console swagger key' },
  { id: 'data_exfiltration', label: 'Data exfiltration', source: 'console swagger key' },
  { id: 'tool_abuse', label: 'Tool abuse', source: 'console swagger key' },
  { id: 'hidden_instructions', label: 'Hidden instructions', source: 'console swagger key' },
  { id: 'pii', label: 'Personal data (PII)', source: 'console swagger key' },
  { id: 'inter_agent_abuse', label: 'Inter-agent abuse', source: 'console swagger key' },
  { id: 'tool_poisoning', label: 'Tool poisoning', source: 'console swagger key' },
  { id: 'memory_poisoning', label: 'Memory poisoning', source: 'console swagger key' },
  { id: 'malicious_content', label: 'Malicious content', source: 'console swagger key' },
  { id: 'schema_violation', label: 'Schema violation', source: 'console swagger key' },
  { id: 'indirect_injection', label: 'Indirect injection', source: 'deck name, no swagger key' },
  { id: 'secrets', label: 'Secrets and credentials', source: 'lab-invented (the schema has no such key)' },
];
export const CATEGORY_IDS = CATEGORIES.map((c) => c.id);
export const isCategory = (id) => typeof id === 'string' && Object.hasOwn(CATEGORY_INDEX, id);
const CATEGORY_INDEX = Object.fromEntries(CATEGORY_IDS.map((id) => [id, true]));
export const NOT_IMPLEMENTED_CATEGORY = { id: 'external_guardrail', label: 'External guardrail (bring your own model)', note: 'Named by the deck and a swagger key; it needs a model behind an HTTP contract, which this lab does not have. Not implemented.' };

// Where content can come from. `out` roles are what the model or agent produced; the rest is content going in.
export const ROLES = [
  { id: 'user_prompt', direction: 'in', label: 'User prompt' },
  { id: 'tool_result', direction: 'in', label: 'Tool result' },
  { id: 'resource', direction: 'in', label: 'Retrieved resource' },
  { id: 'agent_message', direction: 'in', label: 'Message from a peer agent' },
  { id: 'memory_write', direction: 'in', label: 'Memory write' },
  { id: 'tool_definition', direction: 'in', label: 'Tool definition' },
  { id: 'model_output', direction: 'out', label: 'Model output' },
  { id: 'tool_call', direction: 'out', label: 'Tool call' },
];
export const ROLE_IDS = ROLES.map((r) => r.id);
export const isRole = (id) => typeof id === 'string' && ROLE_IDS.includes(id);
export const roleDirection = (id) => ROLES.find((r) => r.id === id).direction;
export const SURFACES = ['llm', 'mcp', 'a2a', 'coding_agent']; // modelPromptLogConfig.Surfaces (console swagger names)
export const isSurface = (id) => typeof id === 'string' && SURFACES.includes(id);

export const TIERS = ['allow', 'alert', 'sanitize', 'block'];
export const TIER_RANK = { allow: 0, alert: 1, sanitize: 2, block: 3 };
const DEFAULT = { AlertThreshold: 0.3, SanitizeThreshold: 0.6, BlockThreshold: 0.8 };
export const DEFAULT_THRESHOLDS = Object.fromEntries(CATEGORY_IDS.map((id) => [id, { ...DEFAULT }]));
DEFAULT_THRESHOLDS.pii = { AlertThreshold: 0.3, SanitizeThreshold: 0.6, BlockThreshold: 0 }; // 0 disables a tier: personal data is redacted, not blocked
DEFAULT_THRESHOLDS.secrets = { AlertThreshold: 0.3, SanitizeThreshold: 0, BlockThreshold: 0.8 };
export const THRESHOLD_FIELDS = ['AlertThreshold', 'SanitizeThreshold', 'BlockThreshold'];
