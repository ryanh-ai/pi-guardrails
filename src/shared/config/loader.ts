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
    await super.load();
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
    await super.save(scope, ensureConfigVersion(config));
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
   * Record pi's project trust decision (ctx.isProjectTrusted() at session
   * start) and re-merge. A trusted project's config is honored as is; an
   * untrusted one may only tighten protection (see sanitizeUntrustedLocal).
   */
  setProjectTrusted(trusted: boolean): void {
    if (trusted === this.projectTrusted) return;
    this.projectTrusted = trusted;
    this.remerge();
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
    // Upstream merges the raw files before remerge() runs on cleaned copies.
    // A malformed file must not make that first merge throw.
    afterMerge: (resolved, global, local, memory) => {
      try {
        return resolveScopes(resolved, global, local, memory);
      } catch {
        return resolved;
      }
    },
  });
}

function resolveScopes(
  resolved: ResolvedConfig,
  global: GuardrailsConfig | null,
  local: GuardrailsConfig | null,
  memory: GuardrailsConfig | null,
): ResolvedConfig {
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
}

export const configLoader = createGuardrailsConfigLoader();

/**
 * Apply pi's project trust decision to the shared loader. pi before 0.84.3
 * has no ctx.isProjectTrusted(); keep upstream behavior there (trusted).
 */
export function syncProjectTrust(ctx: {
  isProjectTrusted?: () => boolean;
}): void {
  configLoader.setProjectTrusted(
    typeof ctx.isProjectTrusted === "function" ? ctx.isProjectTrusted() : true,
  );
}
