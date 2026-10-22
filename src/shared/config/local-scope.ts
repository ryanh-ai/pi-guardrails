import type { GuardrailsConfig, PolicyRule } from "./types";

/**
 * Remove project-local settings that would weaken protection.
 *
 * Anything inside a project, including the agent through write/edit/bash,
 * can create `.pi/extensions/guardrails.json`. Local config may still add
 * rules and patterns, but it can't switch guardrails off, skip prompts, or
 * replace a rule defined by the defaults or the global config.
 *
 * Returns the sanitized copy and the dotted keys that were dropped.
 */
export function sanitizeLocalConfig(
  local: GuardrailsConfig,
  protectedRuleIds: ReadonlySet<string>,
): { config: GuardrailsConfig; ignored: string[] } {
  const config = structuredClone(local);
  const ignored: string[] = [];

  if (config.enabled === false) {
    delete config.enabled;
    ignored.push("enabled");
  }
  if (config.applyBuiltinDefaults === false) {
    delete config.applyBuiltinDefaults;
    ignored.push("applyBuiltinDefaults");
  }

  if (config.features) {
    const features = config.features as Record<string, unknown>;
    for (const [key, value] of Object.entries(features)) {
      if (value === false) {
        delete features[key];
        ignored.push(`features.${key}`);
      }
    }
  }

  const gate = config.permissionGate;
  if (gate) {
    // Not in the raw type, but the deep merge copies it if present.
    const rawGate = gate as Record<string, unknown>;
    if (rawGate.useBuiltinMatchers === false) {
      delete rawGate.useBuiltinMatchers;
      ignored.push("permissionGate.useBuiltinMatchers");
    }
    if (gate.requireConfirmation === false) {
      delete gate.requireConfirmation;
      ignored.push("permissionGate.requireConfirmation");
    }
    if (gate.customPatterns !== undefined) {
      delete gate.customPatterns;
      ignored.push("permissionGate.customPatterns");
    }
    if (gate.allowedPatterns !== undefined) {
      if (gate.allowedPatterns.length > 0) {
        ignored.push("permissionGate.allowedPatterns");
      }
      delete gate.allowedPatterns;
    }
  }

  if (config.policies?.rules) {
    const kept: PolicyRule[] = [];
    for (const rule of config.policies.rules) {
      if (rule && protectedRuleIds.has(rule.id)) {
        ignored.push(`policies.rules[${rule.id}]`);
        continue;
      }
      kept.push(rule);
    }
    config.policies.rules = kept;
  }

  return { config, ignored };
}
