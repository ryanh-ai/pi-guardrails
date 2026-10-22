import type { GuardrailsConfig } from "./types";

const BOOLEAN_KEYS = ["enabled", "applyBuiltinDefaults"] as const;
const GATE_BOOLEAN_KEYS = [
  "useBuiltinMatchers",
  "requireConfirmation",
] as const;
const GATE_PATTERN_LISTS = [
  "patterns",
  "customPatterns",
  "allowedPatterns",
  "autoDenyPatterns",
] as const;
const PROTECTIONS = new Set(["none", "readOnly", "noAccess"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPattern(value: unknown): boolean {
  return isObject(value) && typeof value.pattern === "string";
}

/**
 * Drop values with the wrong type so a hand-edited or hostile config can't
 * crash the loader (which would leave every tool call unguarded) or coerce
 * a check off (`"enabled": 0` is falsy). Returns the cleaned copy and a
 * description of every dropped value.
 */
export function normalizeConfigShape(raw: unknown): {
  config: GuardrailsConfig;
  issues: string[];
} {
  const issues: string[] = [];
  if (!isObject(raw)) {
    return { config: {}, issues: ["config is not a JSON object"] };
  }
  const config = structuredClone(raw) as Record<string, unknown>;

  for (const key of BOOLEAN_KEYS) {
    if (key in config && typeof config[key] !== "boolean") {
      delete config[key];
      issues.push(key);
    }
  }

  if ("features" in config) {
    if (!isObject(config.features)) {
      delete config.features;
      issues.push("features");
    } else {
      for (const [key, value] of Object.entries(config.features)) {
        if (typeof value !== "boolean") {
          delete config.features[key];
          issues.push(`features.${key}`);
        }
      }
    }
  }

  if ("permissionGate" in config) {
    if (!isObject(config.permissionGate)) {
      delete config.permissionGate;
      issues.push("permissionGate");
    } else {
      const gate = config.permissionGate;
      for (const key of GATE_BOOLEAN_KEYS) {
        if (key in gate && typeof gate[key] !== "boolean") {
          delete gate[key];
          issues.push(`permissionGate.${key}`);
        }
      }
      for (const key of GATE_PATTERN_LISTS) {
        if (!(key in gate)) continue;
        const list = gate[key];
        if (!Array.isArray(list)) {
          delete gate[key];
          issues.push(`permissionGate.${key}`);
          continue;
        }
        const valid = list.filter(isPattern);
        if (valid.length !== list.length) {
          issues.push(`permissionGate.${key}[invalid entries]`);
          gate[key] = valid;
        }
      }
    }
  }

  if ("policies" in config) {
    const policies = config.policies;
    if (!isObject(policies) || !Array.isArray(policies.rules ?? [])) {
      delete config.policies;
      issues.push("policies");
    } else if (Array.isArray(policies.rules)) {
      const valid = policies.rules.filter(
        (rule: unknown) =>
          isObject(rule) &&
          typeof rule.id === "string" &&
          Array.isArray(rule.patterns) &&
          rule.patterns.every(isPattern) &&
          (rule.allowedPatterns === undefined ||
            (Array.isArray(rule.allowedPatterns) &&
              rule.allowedPatterns.every(isPattern))) &&
          PROTECTIONS.has(rule.protection as string) &&
          (rule.enabled === undefined || typeof rule.enabled === "boolean"),
      );
      if (valid.length !== policies.rules.length) {
        issues.push("policies.rules[invalid entries]");
        policies.rules = valid;
      }
    }
  }

  if ("pathAccess" in config && !isObject(config.pathAccess)) {
    delete config.pathAccess;
    issues.push("pathAccess");
  }

  return { config: config as GuardrailsConfig, issues };
}
