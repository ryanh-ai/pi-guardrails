import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import {
  buildSchemaUrl,
  ConfigLoader,
  type Scope,
} from "@aliou/pi-utils-settings";
import pkg from "../../../package.json" with { type: "json" };
import type { AllowedPath } from "../../core/paths/path";
import { DEFAULT_CONFIG } from "./defaults";
import { type ConfigFileState, probeConfigFile } from "./health";
import { sanitizeUntrustedLocal } from "./local-scope";
import { migrations } from "./migration";
import { normalizeConfigShape } from "./shape";
import type { GuardrailsConfig, PolicyRule, ResolvedConfig } from "./types";

/**
 * The parts of pi-utils-settings' ConfigLoader that `remerge` relies on. They
 * are private upstream; config-loader.test.ts fails if they change.
 */
interface LoaderInternals {
  globalPath: string | null;
  localPath: string | null;
  globalConfig: GuardrailsConfig | null;
  localConfig: GuardrailsConfig | null;
  resolved: ResolvedConfig | null;
  merge(): ResolvedConfig;
}

export interface ShapeIssues {
  global: string[];
  local: string[];
}

class GuardrailsConfigLoader extends ConfigLoader<
  GuardrailsConfig,
  ResolvedConfig
> {
  private shapeIssues: ShapeIssues = { global: [], local: [] };
  /** Until pi reports trust at session start, treat the project as untrusted. */
  private projectTrusted = false;
  private ignoredLocalKeys: string[] = [];
  private fileStates: { global?: ConfigFileState; local?: ConfigFileState } =
    {};

  /**
   * Load and save as upstream does, then merge again from shape-checked
   * copies of the file configs (see remerge).
   */
  override async load(): Promise<void> {
    await this.probeFiles();
    try {
      await super.load();
    } catch (error) {
      // Reads and migrations never throw upstream; only the merge of a
      // malformed file can. remerge() merges cleaned copies instead.
      if (isFileSystemError(error)) throw error;
    }
    this.remerge();
  }

  /**
   * Refuse to write over a settings file that exists but can't be read. The
   * loader saw it as empty, so saving would replace it with just the new
   * values. Health is re-checked now, not taken from load time.
   */
  override async save(scope: Scope, config: GuardrailsConfig): Promise<void> {
    const path =
      scope === "global"
        ? this.internals().globalPath
        : scope === "local"
          ? this.internals().localPath
          : null;
    if (path) {
      const state = await probeConfigFile(path);
      if (state.state === "broken") {
        throw new Error(
          `Refusing to overwrite ${path}: ${state.reason}. Fix the file, then /reload.`,
        );
      }
    }
    try {
      await super.save(scope, ensureConfigVersion(config));
    } catch (error) {
      // The write happens before the merge; only a write failure or a bad
      // scope should surface. A malformed file breaking the merge is handled
      // by remerge().
      if (isFileSystemError(error) || !(error instanceof TypeError))
        throw error;
    }
    this.remerge();
  }

  /** Global and project settings file health from the last load. */
  getFileStates(): { global?: ConfigFileState; local?: ConfigFileState } {
    return this.fileStates;
  }

  private async probeFiles(): Promise<void> {
    const { globalPath, localPath } = this.internals();
    this.fileStates = {
      global: globalPath ? await probeConfigFile(globalPath) : undefined,
      local: localPath ? await probeConfigFile(localPath) : undefined,
    };
  }

  /** Values dropped or fixed because they had the wrong type. */
  getShapeIssues(): ShapeIssues {
    return this.shapeIssues;
  }

  /**
   * Re-run upstream's merge on cleaned copies of the file configs. The raw
   * configs stay in place for getRawConfig() and saves.
   */
  protected remerge(): void {
    const internals = this.internals();

    // Strip __proto__/constructor/prototype keys from the raw configs in-place
    // and undo any Object.prototype pollution from upstream's deepMerge in
    // super.load(). Must run before we capture rawGlobal / rawLocal so the
    // restored references are already clean.
    removeProtoPollutionFromRaw(
      internals.globalConfig as unknown as Record<string, unknown> | null,
    );
    removeProtoPollutionFromRaw(
      internals.localConfig as unknown as Record<string, unknown> | null,
    );

    const rawGlobal = internals.globalConfig;
    const rawLocal = internals.localConfig;
    this.ignoredLocalKeys = [];
    const global = rawGlobal ? normalizeConfigShape(rawGlobal) : null;
    const local = rawLocal ? normalizeConfigShape(rawLocal) : null;
    this.shapeIssues = {
      global: global?.issues ?? [],
      local: local?.issues ?? [],
    };
    internals.globalConfig = global?.config ?? null;
    internals.localConfig = local
      ? this.restrictLocal(local.config, global?.config ?? null)
      : null;
    try {
      internals.resolved = internals.merge();
    } finally {
      internals.globalConfig = rawGlobal;
      internals.localConfig = rawLocal;
    }
  }

  /**
   * Record pi's project trust decision and the session cwd, then re-merge.
   *
   * `piTrusted` is the result of `ctx.isProjectTrusted()` when available,
   * or `undefined` for older pi versions that lack the method.
   * `cwd` is `ctx.cwd` from the `session_start` context.
   *
   * A project is treated as trusted only when:
   *   - pi says it is trusted (`piTrusted === true`), AND
   *   - the project config's root directory matches `cwd` (after realpath
   *     canonicalization where possible) — prevents an ancestor `.pi` from
   *     silently getting trusted semantics for a session in a subdirectory.
   *
   * Old-pi fallback (`piTrusted === undefined`): if `cwd` is provided, the
   * project is trusted only when the roots match; if `cwd` is absent (very
   * old pi context), the old behavior (always trusted) is preserved.
   */
  setProjectTrusted(piTrusted: boolean | undefined, cwd?: string): void {
    const trusted = this.computeEffectiveTrust(piTrusted, cwd);
    if (trusted === this.projectTrusted) return;
    this.projectTrusted = trusted;
    this.remerge();
  }

  /** Whether the current project is considered trusted. */
  isProjectTrusted(): boolean {
    return this.projectTrusted;
  }

  /**
   * Compute the effective trust value from pi's answer and the cwd root check.
   * See `setProjectTrusted` for the full rules.
   */
  private computeEffectiveTrust(
    piTrusted: boolean | undefined,
    cwd: string | undefined,
  ): boolean {
    // No cwd: cannot do root check; fall back to pi's answer (or true for old pi).
    if (!cwd) return piTrusted ?? true;

    const { localPath } = this.internals();
    // No local config: trust doesn't matter (sanitization won't run).
    if (!localPath) return piTrusted ?? true;

    // localPath = <root>/.pi/extensions/guardrails.json
    const configRoot = dirname(dirname(dirname(localPath)));
    let rootsMatch: boolean;
    try {
      rootsMatch = realpathSync(configRoot) === realpathSync(cwd);
    } catch {
      // If realpath fails (e.g. in-memory fs or non-existent path), fall back
      // to a plain string comparison.
      rootsMatch = configRoot === cwd;
    }

    if (piTrusted === undefined) {
      // Old pi: trust only when roots match (if cwd available).
      return rootsMatch;
    }
    return piTrusted && rootsMatch;
  }

  /** Project keys ignored because the project is untrusted. */
  getIgnoredLocalKeys(): string[] {
    return this.ignoredLocalKeys;
  }

  private restrictLocal(
    local: GuardrailsConfig,
    global: GuardrailsConfig | null,
  ): GuardrailsConfig {
    this.ignoredLocalKeys = [];
    if (this.projectTrusted) return local;
    const protectedRuleIds = new Set<string>([
      ...DEFAULT_CONFIG.policies.rules.map((rule) => rule.id),
      ...(global?.policies?.rules ?? []).map((rule) => rule.id),
    ]);
    const { config, ignored } = sanitizeUntrustedLocal(
      local,
      protectedRuleIds,
      {
        mode: global?.pathAccess?.mode ?? DEFAULT_CONFIG.pathAccess.mode,
        applyTo:
          global?.pathAccess?.applyTo ?? DEFAULT_CONFIG.pathAccess.applyTo,
      },
    );
    this.ignoredLocalKeys = ignored;
    return config;
  }

  private internals(): LoaderInternals {
    const internals = this as unknown as LoaderInternals;
    if (typeof internals.merge !== "function") {
      throw new Error(
        "[guardrails] pi-utils-settings ConfigLoader internals changed: update GuardrailsConfigLoader",
      );
    }
    return internals;
  }
}

function isFileSystemError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error;
}

/**
 * Strip __proto__, constructor, and prototype keys from a raw config object
 * in place (so future deepMerge calls won't see them), and delete any
 * own properties they added to Object.prototype via upstream's deepMerge.
 *
 * Uses Object.getOwnPropertyDescriptor throughout to bypass the __proto__
 * accessor and operate on actual own properties.
 */
const PROTO_POLLUTION_RAW_KEYS = [
  "__proto__",
  "constructor",
  "prototype",
] as const;

function removeProtoPollutionFromRaw(
  obj: Record<string, unknown> | null | undefined,
): void {
  if (!obj || typeof obj !== "object") return;
  for (const key of PROTO_POLLUTION_RAW_KEYS) {
    const ownDesc = Object.getOwnPropertyDescriptor(obj, key);
    if (!ownDesc) continue;
    const injected = ownDesc.value;
    if (injected && typeof injected === "object" && !Array.isArray(injected)) {
      // The upstream deepMerge iterated injected's own keys and assigned them
      // to Object.prototype.  Remove those own properties now.
      for (const pollutedKey of Object.keys(injected as object)) {
        const propDesc = Object.getOwnPropertyDescriptor(
          Object.prototype,
          pollutedKey,
        );
        if (propDesc?.configurable) {
          try {
            delete (Object.prototype as Record<string, unknown>)[pollutedKey];
          } catch {
            // Defensive: ignore if delete unexpectedly throws.
          }
        }
      }
    }
    delete obj[key];
  }
  // Recurse into remaining own enumerable child values.
  for (const value of Object.values(obj)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        removeProtoPollutionFromRaw(item as Record<string, unknown>);
      }
    } else if (value && typeof value === "object") {
      removeProtoPollutionFromRaw(value as Record<string, unknown>);
    }
  }
}

function ensureConfigVersion(config: GuardrailsConfig): GuardrailsConfig {
  if (typeof config.version === "string" && config.version.trim()) {
    return config;
  }
  return { ...config, version: pkg.version };
}

function mergePatternArrays<T extends { pattern: string }>(
  ...lists: (T[] | undefined)[]
): T[] {
  const merged = new Map<string, T>();
  for (const list of lists) {
    for (const entry of list ?? []) {
      merged.set(entry.pattern, entry);
    }
  }
  return [...merged.values()];
}

export function createGuardrailsConfigLoader(): GuardrailsConfigLoader {
  return new GuardrailsConfigLoader("guardrails", DEFAULT_CONFIG, {
    scopes: ["global", "local", "memory"],
    migrations,
    schemaUrl: buildSchemaUrl(pkg.name, pkg.version),
    afterMerge: (resolved, global, local, memory) => {
      const ruleMap = new Map<string, PolicyRule>();

      if (resolved.applyBuiltinDefaults) {
        for (const rule of DEFAULT_CONFIG.policies.rules) {
          ruleMap.set(rule.id, rule);
        }
      }
      if (global?.policies?.rules) {
        for (const rule of global.policies.rules) {
          ruleMap.set(rule.id, rule);
        }
      }
      if (local?.policies?.rules) {
        for (const rule of local.policies.rules) {
          ruleMap.set(rule.id, rule);
        }
      }
      if (memory?.policies?.rules) {
        for (const rule of memory.policies.rules) {
          ruleMap.set(rule.id, rule);
        }
      }
      resolved.policies.rules = [...ruleMap.values()];

      // Pattern arrays union across scopes by `pattern`; customPatterns
      // still replaces patterns wholesale.
      const customPatterns =
        memory?.permissionGate?.customPatterns ??
        local?.permissionGate?.customPatterns ??
        global?.permissionGate?.customPatterns;
      if (customPatterns) {
        resolved.permissionGate.patterns = customPatterns;
        resolved.permissionGate.useBuiltinMatchers = false;
      } else {
        resolved.permissionGate.patterns = mergePatternArrays(
          DEFAULT_CONFIG.permissionGate.patterns,
          global?.permissionGate?.patterns,
          local?.permissionGate?.patterns,
          memory?.permissionGate?.patterns,
        );
      }

      resolved.permissionGate.allowedPatterns = mergePatternArrays(
        global?.permissionGate?.allowedPatterns,
        local?.permissionGate?.allowedPatterns,
        memory?.permissionGate?.allowedPatterns,
      );

      resolved.permissionGate.autoDenyPatterns = mergePatternArrays(
        global?.permissionGate?.autoDenyPatterns,
        local?.permissionGate?.autoDenyPatterns,
        memory?.permissionGate?.autoDenyPatterns,
      );

      const mergedPaths = new Map<string, AllowedPath>();
      for (const paths of [
        global?.pathAccess?.allowedPaths,
        local?.pathAccess?.allowedPaths,
        memory?.pathAccess?.allowedPaths,
      ]) {
        for (const entry of paths ?? []) {
          if (!entry || typeof entry !== "object") continue;
          const path = typeof entry.path === "string" ? entry.path.trim() : "";
          if (!path) continue;
          const kind = entry.kind === "directory" ? "directory" : "file";
          mergedPaths.set(`${kind}:${path}`, { kind, path });
        }
      }
      resolved.pathAccess.allowedPaths = [...mergedPaths.values()];

      // alwaysScope: highest-priority scope wins (memory > local > global).
      // Invalid values are ignored so they cannot leak through the base
      // deep merge into the resolved config.
      const alwaysScope = [memory, local, global]
        .map((scope) => scope?.pathAccess?.alwaysScope)
        .find((value) => value === "local" || value === "global");
      resolved.pathAccess.alwaysScope = alwaysScope ?? "local";

      return resolved;
    },
  });
}

export const configLoader = createGuardrailsConfigLoader();

/**
 * Apply pi's project trust decision to the shared loader. pi before 0.84.3
 * has no ctx.isProjectTrusted(); keep upstream behavior there (trusted when
 * the project config's root matches cwd, else untrusted).
 */
export function syncProjectTrust(ctx: {
  isProjectTrusted?: () => boolean;
  cwd?: string;
}): void {
  configLoader.setProjectTrusted(
    typeof ctx.isProjectTrusted === "function"
      ? ctx.isProjectTrusted()
      : undefined,
    ctx.cwd,
  );
}
