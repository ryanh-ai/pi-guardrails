import type { GuardrailsConfig, PolicyRule } from "./types";

/**
 * Remove project settings that would loosen protection, for projects pi
 * does not trust.
 *
 * pi asks before trusting a project with `.pi/extensions` (where the project
 * guardrails file lives). In a trusted project the file is honored as is,
 * like upstream. In an untrusted one it may still add rules and patterns, but
 * these are ignored:
 *
 * - `enabled`, `applyBuiltinDefaults`, `features.*`,
 *   `permissionGate.useBuiltinMatchers`, `permissionGate.requireConfirmation`
 *   set to `false`
 * - `permissionGate.customPatterns` (replaces the built-in patterns) and
 *   `permissionGate.allowedPatterns`
 * - policy rules reusing a built-in or global rule id
 * - `pathAccess.mode` / `pathAccess.applyTo` looser than the global setting,
 *   and `pathAccess.allowedPaths`
 *
 * Expects a shape-checked config (see normalizeConfigShape). Returns the
 * filtered copy and the dotted keys that were ignored.
 */
const MODE_RANK: Record<string, number> = { allow: 0, ask: 1, block: 2 };
const APPLY_TO_RANK: Record<string, number> = { write: 0, all: 1 };

export function sanitizeUntrustedLocal(
  local: GuardrailsConfig,
  protectedRuleIds: ReadonlySet<string>,
  global: { mode: string; applyTo: string },
): { config: GuardrailsConfig; ignored: string[] } {
  const config = structuredClone(local);
  const ignored: string[] = [];
  const drop = (owner: Record<string, unknown>, key: string, label: string) => {
    delete owner[key];
    ignored.push(label);
  };
  const root = config as Record<string, unknown>;

  for (const key of ["enabled", "applyBuiltinDefaults"]) {
    if (root[key] === false) drop(root, key, key);
  }

  if (config.features) {
    const features = config.features as Record<string, unknown>;
    for (const [key, value] of Object.entries(features)) {
      if (value === false) drop(features, key, `features.${key}`);
    }
  }

  if (config.permissionGate) {
    const gate = config.permissionGate as Record<string, unknown>;
    for (const key of ["useBuiltinMatchers", "requireConfirmation"]) {
      if (gate[key] === false) drop(gate, key, `permissionGate.${key}`);
    }
    if (gate.customPatterns !== undefined) {
      drop(gate, "customPatterns", "permissionGate.customPatterns");
    }
    if (
      Array.isArray(gate.allowedPatterns) &&
      gate.allowedPatterns.length > 0
    ) {
      drop(gate, "allowedPatterns", "permissionGate.allowedPatterns");
    }
  }

  if (config.policies?.rules) {
    const kept: PolicyRule[] = [];
    for (const rule of config.policies.rules) {
      if (protectedRuleIds.has(rule.id)) {
        ignored.push(`policies.rules[${rule.id}]`);
      } else {
        kept.push(rule);
      }
    }
    config.policies.rules = kept;
  }

  if (config.pathAccess) {
    const access = config.pathAccess as Record<string, unknown>;
    if (
      access.mode !== undefined &&
      (MODE_RANK[access.mode as string] ?? 0) < (MODE_RANK[global.mode] ?? 1)
    ) {
      drop(access, "mode", "pathAccess.mode");
    }
    if (
      access.applyTo !== undefined &&
      (APPLY_TO_RANK[access.applyTo as string] ?? 0) <
        (APPLY_TO_RANK[global.applyTo] ?? 1)
    ) {
      drop(access, "applyTo", "pathAccess.applyTo");
    }
    if (Array.isArray(access.allowedPaths) && access.allowedPaths.length > 0) {
      drop(access, "allowedPaths", "pathAccess.allowedPaths");
    }
  }

  return { config, ignored };
}
