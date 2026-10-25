import type { GuardrailsConfig } from "./types";

/**
 * Validate a raw config file's shape before it is merged.
 *
 * Valid JSON can still have the wrong types. `"enabled": 0` is falsy and
 * switches guardrails off; a non-array `allowedPaths` or a `null` rule throws
 * during the merge and takes every check down with it. This drops or fixes
 * only the offending value and reports it.
 *
 * Never loosen a config while fixing it:
 * - `__proto__`, `constructor`, and `prototype` keys are stripped at every
 *   depth before any other processing (prototype-pollution guard);
 * - invalid entries in allow lists are dropped (fewer exceptions);
 * - an invalid flag whose default is the stricter choice is dropped;
 * - an invalid flag whose default is the looser choice is set to the
 *   stricter value (`onlyIfExists`, `respectCwd` → false);
 * - a rule with an invalid `protection` becomes `noAccess`;
 * - a truthy non-boolean `regex`/`terminate` on deny/ask pattern lists is
 *   kept as `true` — dropping it would silently disable a deny rule.
 *   On allow lists, non-boolean `regex` is still dropped (fewer exceptions).
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

  // Strip prototype-pollution keys before any other processing.
  stripProtoPollutionKeys(config, issues, "");

  for (const key of ["enabled", "applyBuiltinDefaults"]) {
    dropUnlessBoolean(config, key, key, issues);
  }

  if ("features" in config) {
    if (!isObject(config.features)) {
      drop(config, "features", "features", issues);
    } else {
      for (const key of Object.keys(config.features)) {
        dropUnlessBoolean(config.features, key, `features.${key}`, issues);
      }
    }
  }

  normalizePermissionGate(config, issues);
  normalizePolicies(config, issues);
  normalizePathAccess(config, issues);

  return { config: config as GuardrailsConfig, issues };
}

type Record_ = Record<string, unknown>;

function isObject(value: unknown): value is Record_ {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Recursively strip keys that could cause prototype pollution (`__proto__`,
 * `constructor`, `prototype`). Called on the structuredClone before any other
 * shape normalisation so that deepMerge never iterates over them.
 */
const PROTO_POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function stripProtoPollutionKeys(
  node: unknown,
  issues: string[],
  path: string,
): void {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      stripProtoPollutionKeys(node[i], issues, `${path}[${i}]`);
    }
  } else if (isObject(node)) {
    for (const key of PROTO_POLLUTION_KEYS) {
      if (Object.hasOwn(node, key)) {
        delete node[key];
        issues.push(
          `${path ? `${path}.` : ""}${key} (prototype pollution key stripped)`,
        );
      }
    }
    for (const [key, value] of Object.entries(node)) {
      stripProtoPollutionKeys(value, issues, path ? `${path}.${key}` : key);
    }
  }
}

function drop(target: Record_, key: string, label: string, issues: string[]) {
  delete target[key];
  issues.push(label);
}

function dropUnlessBoolean(
  target: Record_,
  key: string,
  label: string,
  issues: string[],
) {
  if (key in target && typeof target[key] !== "boolean") {
    drop(target, key, label, issues);
  }
}

function dropUnlessString(
  target: Record_,
  key: string,
  label: string,
  issues: string[],
) {
  if (key in target && typeof target[key] !== "string") {
    drop(target, key, label, issues);
  }
}

/** Clean one pattern entry in place. Returns false if it is unusable. */
function normalizePattern(
  entry: unknown,
  label: string,
  issues: string[],
  coerceBooleans = false,
): boolean {
  if (!isObject(entry) || typeof entry.pattern !== "string") return false;
  if (coerceBooleans) {
    // Deny/ask lists: a truthy non-boolean regex/terminate is kept as `true`.
    // Dropping it would silently disable a deny rule.
    for (const key of ["regex", "terminate"] as const) {
      if (key in entry && typeof entry[key] !== "boolean") {
        if (entry[key]) {
          entry[key] = true;
          issues.push(`${label}.${key} (coerced to true)`);
        } else {
          delete entry[key];
          issues.push(`${label}.${key}`);
        }
      }
    }
  } else {
    dropUnlessBoolean(entry, "regex", `${label}.regex`, issues);
    dropUnlessBoolean(entry, "terminate", `${label}.terminate`, issues);
  }
  dropUnlessString(entry, "description", `${label}.description`, issues);
  return true;
}

/** Keep the valid entries of a pattern list; drop the list if not an array. */
function normalizePatternList(
  owner: Record_,
  key: string,
  label: string,
  issues: string[],
  coerceBooleans = false,
): void {
  if (!(key in owner)) return;
  const list = owner[key];
  if (!Array.isArray(list)) {
    drop(owner, key, label, issues);
    return;
  }
  const valid = list.filter((entry, index) =>
    normalizePattern(entry, `${label}[${index}]`, issues, coerceBooleans),
  );
  if (valid.length !== list.length) {
    issues.push(`${label}[${list.length - valid.length} invalid entries]`);
    owner[key] = valid;
  }
}

function normalizePermissionGate(config: Record_, issues: string[]): void {
  if (!("permissionGate" in config)) return;
  const gate = config.permissionGate;
  if (!isObject(gate)) {
    drop(config, "permissionGate", "permissionGate", issues);
    return;
  }
  for (const key of ["requireConfirmation", "useBuiltinMatchers"]) {
    dropUnlessBoolean(gate, key, `permissionGate.${key}`, issues);
  }
  for (const key of ["patterns", "customPatterns", "autoDenyPatterns"]) {
    normalizePatternList(gate, key, `permissionGate.${key}`, issues, true);
  }
  // allowedPatterns: drop non-boolean regex (fewer exceptions on allow lists).
  normalizePatternList(
    gate,
    "allowedPatterns",
    "permissionGate.allowedPatterns",
    issues,
    false,
  );
}

const PROTECTIONS = new Set(["none", "readOnly", "noAccess"]);

function normalizePolicies(config: Record_, issues: string[]): void {
  if (!("policies" in config)) return;
  const policies = config.policies;
  if (!isObject(policies)) {
    drop(config, "policies", "policies", issues);
    return;
  }
  if (!("rules" in policies)) return;
  if (!Array.isArray(policies.rules)) {
    drop(policies, "rules", "policies.rules", issues);
    return;
  }
  policies.rules = policies.rules.filter((rule, index) => {
    const label = `policies.rules[${isObject(rule) && typeof rule.id === "string" ? rule.id : index}]`;
    if (!isObject(rule) || typeof rule.id !== "string" || !rule.id.trim()) {
      issues.push(`${label} (no id)`);
      return false;
    }
    if (!PROTECTIONS.has(rule.protection as string)) {
      rule.protection = "noAccess";
      issues.push(`${label}.protection (set to noAccess)`);
    }
    for (const key of ["name", "description", "blockMessage"]) {
      dropUnlessString(rule, key, `${label}.${key}`, issues);
    }
    // Default true is the stricter choice for `enabled`.
    dropUnlessBoolean(rule, "enabled", `${label}.enabled`, issues);
    // Defaults are the looser choice here, so fix to the stricter value.
    for (const key of ["onlyIfExists", "respectCwd"]) {
      if (key in rule && typeof rule[key] !== "boolean") {
        rule[key] = false;
        issues.push(`${label}.${key} (set to false)`);
      }
    }
    normalizePatternList(
      rule,
      "allowedPatterns",
      `${label}.allowedPatterns`,
      issues,
      false, // allow list: drop non-boolean regex
    );
    if (!Array.isArray(rule.patterns)) {
      issues.push(`${label}.patterns (not a list)`);
      return false;
    }
    normalizePatternList(rule, "patterns", `${label}.patterns`, issues, true); // coerce for deny list
    if ((rule.patterns as unknown[]).length === 0) {
      issues.push(`${label} (no valid patterns)`);
      return false;
    }
    return true;
  });
}

const MODES = new Set(["allow", "ask", "block"]);
const APPLY_TO = new Set(["all", "write"]);
const SCOPES = new Set(["local", "global"]);

function normalizePathAccess(config: Record_, issues: string[]): void {
  if (!("pathAccess" in config)) return;
  const access = config.pathAccess;
  if (!isObject(access)) {
    drop(config, "pathAccess", "pathAccess", issues);
    return;
  }
  // Defaults ("ask", "all") are the stricter choices.
  if ("mode" in access && !MODES.has(access.mode as string)) {
    drop(access, "mode", "pathAccess.mode", issues);
  }
  if ("applyTo" in access && !APPLY_TO.has(access.applyTo as string)) {
    drop(access, "applyTo", "pathAccess.applyTo", issues);
  }
  if ("alwaysScope" in access && !SCOPES.has(access.alwaysScope as string)) {
    drop(access, "alwaysScope", "pathAccess.alwaysScope", issues);
  }
  if ("allowedPaths" in access) {
    const list = access.allowedPaths;
    if (!Array.isArray(list)) {
      drop(access, "allowedPaths", "pathAccess.allowedPaths", issues);
    } else {
      const valid = list.filter(
        (entry) =>
          isObject(entry) &&
          typeof entry.path === "string" &&
          (entry.kind === "file" || entry.kind === "directory"),
      );
      if (valid.length !== list.length) {
        issues.push(
          `pathAccess.allowedPaths[${list.length - valid.length} invalid entries]`,
        );
        access.allowedPaths = valid;
      }
    }
  }
}
