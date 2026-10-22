import {
  buildSchemaUrl,
  ConfigLoader,
  type Scope,
} from "@aliou/pi-utils-settings";
import pkg from "../../../package.json" with { type: "json" };
import type { AllowedPath } from "../../core/paths/path";
import { DEFAULT_CONFIG } from "./defaults";
import {
  type ConfigHealth,
  globalConfigPath,
  localConfigPath,
  probeConfigFile,
  readGlobalSnapshot,
  trustedProjectGrants,
  writeGlobalSnapshot,
} from "./health";
import { sanitizeLocalConfig } from "./local-scope";
import { migrations } from "./migration";
import type { GuardrailsConfig, PolicyRule, ResolvedConfig } from "./types";

/** Mutable load state shared between the loader and its merge hook. */
interface LoadState {
  health: ConfigHealth;
  /** Last good global config, used while the global file is broken. */
  snapshot: GuardrailsConfig | null;
}

function initialHealth(): ConfigHealth {
  return {
    mode: "normal",
    global: { state: "absent", path: globalConfigPath() },
    local: { state: "absent", path: "" },
    ignoredLocalKeys: [],
  };
}

class GuardrailsConfigLoader extends ConfigLoader<
  GuardrailsConfig,
  ResolvedConfig
> {
  constructor(
    private readonly state: LoadState,
    ...args: ConstructorParameters<
      typeof ConfigLoader<GuardrailsConfig, ResolvedConfig>
    >
  ) {
    super(...args);
  }

  /**
   * Probe the config files before the upstream loader reads them. Its read
   * treats a dangling symlink or invalid JSON the same as a missing file,
   * which would silently drop every custom rule.
   */
  override async load(): Promise<void> {
    const globalPath = globalConfigPath();
    const localPath = localConfigPath();
    const global = await probeConfigFile(globalPath);
    const local = localPath
      ? await probeConfigFile(localPath)
      : ({ state: "absent", path: "" } as const);

    const health: ConfigHealth = {
      mode: "normal",
      global,
      local,
      ignoredLocalKeys: [],
    };
    this.state.snapshot = null;
    if (global.state === "broken") {
      const snapshot = await readGlobalSnapshot();
      if (snapshot) {
        this.state.snapshot = snapshot.config;
        health.mode = "snapshot";
        health.snapshotSavedAt = snapshot.savedAt;
      } else {
        health.mode = "fail-closed";
      }
    }
    this.state.health = health;

    await super.load();

    const raw = this.getRawConfig("global");
    if (global.state === "ok" && raw) {
      await writeGlobalSnapshot(raw, globalPath);
    }
  }

  override async save(scope: Scope, config: GuardrailsConfig): Promise<void> {
    const file =
      scope === "global"
        ? this.state.health.global
        : scope === "local"
          ? this.state.health.local
          : undefined;
    if (file?.state === "broken") {
      throw new Error(
        `Refusing to overwrite ${file.path}: ${file.reason}. Fix the file, then /reload.`,
      );
    }
    await super.save(scope, ensureConfigVersion(config));
    const raw = this.getRawConfig("global");
    if (scope === "global" && raw) {
      await writeGlobalSnapshot(raw, globalConfigPath());
    }
  }

  getHealth(): ConfigHealth {
    return this.state.health;
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

/** Same semantics as the settings loader: objects merge, arrays replace. */
function deepMerge(target: object, source: object): void {
  const t = target as Record<string, unknown>;
  const s = source as Record<string, unknown>;
  for (const key in s) {
    if (s[key] === undefined) continue;
    if (
      typeof s[key] === "object" &&
      !Array.isArray(s[key]) &&
      s[key] !== null
    ) {
      if (!t[key] || typeof t[key] !== "object") t[key] = {};
      deepMerge(t[key] as object, s[key] as object);
    } else {
      t[key] = s[key];
    }
  }
}

export function createGuardrailsConfigLoader(): GuardrailsConfigLoader {
  const state: LoadState = { health: initialHealth(), snapshot: null };
  return new GuardrailsConfigLoader(state, "guardrails", DEFAULT_CONFIG, {
    scopes: ["global", "local", "memory"],
    migrations,
    schemaUrl: buildSchemaUrl(pkg.name, pkg.version),
    afterMerge: (_upstreamResolved, rawGlobal, rawLocal, memory) => {
      // Rebuild instead of using the upstream merge: the global scope may come
      // from the last good snapshot, and the local scope is sanitized first.
      const global = rawGlobal ?? state.snapshot;
      const protectedRuleIds = new Set<string>([
        ...DEFAULT_CONFIG.policies.rules.map((rule) => rule.id),
        ...(global?.policies?.rules ?? []).map((rule) => rule.id),
      ]);
      let local: GuardrailsConfig | null = null;
      state.health.ignoredLocalKeys = [];
      if (rawLocal) {
        const sanitized = sanitizeLocalConfig(rawLocal, protectedRuleIds);
        local = sanitized.config;
        state.health.ignoredLocalKeys = sanitized.ignored;
      }

      const resolved = structuredClone(DEFAULT_CONFIG);
      for (const scope of [global, local, memory]) {
        if (scope) deepMerge(resolved, scope);
      }
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

      // Project allow grants come from the trusted store, never from the
      // project's own config file (sanitized above).
      resolved.permissionGate.allowedPatterns = mergePatternArrays(
        global?.permissionGate?.allowedPatterns,
        trustedProjectGrants(),
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
