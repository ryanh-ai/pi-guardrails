import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import { ConfigLoader, type Scope } from "@aliou/pi-utils-settings";
import { DEFAULT_CONFIG } from "./defaults";
import { type ConfigFileState, probeConfigFile } from "./health";
import { sanitizeUntrustedLocal } from "./local-scope";
import { normalizeConfigShape } from "./shape";
import type { GuardrailsConfig, ResolvedConfig } from "./types";

/**
 * Settings loader hardening for the guardrails fork, kept out of loader.ts so
 * the upstream file only changes its base class.
 *
 * On top of pi-utils-settings' ConfigLoader:
 * - shape-checks each settings file before merging (shape.ts);
 * - reports files that exist but can't be read, and refuses to overwrite
 *   them (health.ts);
 * - honors loosening project settings only in a project pi trusts
 *   (local-scope.ts);
 * - strips `__proto__`-style keys and undoes prototype pollution from the
 *   upstream merge.
 *
 * It re-runs upstream's private merge() on cleaned copies of the file
 * configs (see remerge), and serves that result from getConfig().
 */

/**
 * The parts of pi-utils-settings' ConfigLoader that remerge() relies on.
 * They are private upstream; guarded-loader.test.ts fails if they change.
 */
interface LoaderInternals {
  globalPath: string | null;
  localPath: string | null;
  globalConfig: GuardrailsConfig | null;
  localConfig: GuardrailsConfig | null;
  merge(): ResolvedConfig;
}

export interface ShapeIssues {
  global: string[];
  local: string[];
}

export class GuardedConfigLoader extends ConfigLoader<
  GuardrailsConfig,
  ResolvedConfig
> {
  private cleaned: ResolvedConfig | null = null;
  private shapeIssues: ShapeIssues = { global: [], local: [] };
  /** Until pi reports trust at session start, treat the project as untrusted. */
  private projectTrusted = false;
  private ignoredLocalKeys: string[] = [];
  private fileStates: { global?: ConfigFileState; local?: ConfigFileState } =
    {};

  /** Load as upstream does, then merge again from cleaned copies. */
  override async load(): Promise<void> {
    await this.probeFiles();
    try {
      await withPrototypeGuard(() => super.load());
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
    // Surface serialization errors (TypeError) before the write, so the
    // catch below only ever sees merge errors.
    JSON.stringify(config);
    try {
      await withPrototypeGuard(() => super.save(scope, config));
    } catch (error) {
      // The write happens before the merge. A malformed file breaking the
      // merge is handled by remerge(); anything else surfaces.
      if (isFileSystemError(error) || !(error instanceof TypeError)) {
        throw error;
      }
    }
    this.remerge();
  }

  /** The merge of cleaned configs; never upstream's raw merge. */
  override getConfig(): ResolvedConfig {
    return this.cleaned ?? super.getConfig();
  }

  /** Global and project settings file health from the last load. */
  getFileStates(): { global?: ConfigFileState; local?: ConfigFileState } {
    return this.fileStates;
  }

  /** Values dropped or fixed because they had the wrong type. */
  getShapeIssues(): ShapeIssues {
    return this.shapeIssues;
  }

  /** Project keys ignored because the project is untrusted. */
  getIgnoredLocalKeys(): string[] {
    return this.ignoredLocalKeys;
  }

  /** Whether the current project is considered trusted. */
  isProjectTrusted(): boolean {
    return this.projectTrusted;
  }

  /**
   * Record pi's project trust decision and the session cwd, then re-merge.
   *
   * `piTrusted` is `ctx.isProjectTrusted()` when available, or `undefined`
   * on older pi. A project counts as trusted only when pi trusts it AND the
   * project config's root is `cwd`: pi only checks `cwd/.pi`, while the
   * settings loader uses the nearest ancestor `.pi`. On older pi, matching
   * roots alone count as trusted; with no `cwd`, upstream behavior (trusted).
   */
  setProjectTrusted(piTrusted: boolean | undefined, cwd?: string): void {
    const trusted = this.computeEffectiveTrust(piTrusted, cwd);
    if (trusted === this.projectTrusted) return;
    this.projectTrusted = trusted;
    this.remerge();
  }

  private computeEffectiveTrust(
    piTrusted: boolean | undefined,
    cwd: string | undefined,
  ): boolean {
    const { localPath } = this.internals();
    // No cwd or no project config: nothing to compare.
    if (!cwd || !localPath) return piTrusted ?? true;

    // localPath = <root>/.pi/extensions/guardrails.json
    const configRoot = dirname(dirname(dirname(localPath)));
    let rootsMatch: boolean;
    try {
      rootsMatch = realpathSync(configRoot) === realpathSync(cwd);
    } catch {
      rootsMatch = configRoot === cwd;
    }
    return piTrusted === undefined ? rootsMatch : piTrusted && rootsMatch;
  }

  private async probeFiles(): Promise<void> {
    const { globalPath, localPath } = this.internals();
    this.fileStates = {
      global: globalPath ? await probeConfigFile(globalPath) : undefined,
      local: localPath ? await probeConfigFile(localPath) : undefined,
    };
  }

  /**
   * Re-run upstream's merge on cleaned copies of the file configs. The raw
   * configs stay in place for getRawConfig() and saves.
   */
  private remerge(): void {
    const internals = this.internals();
    // Strip __proto__-style keys from the raw configs in place, so later
    // merges and saves never see them.
    stripPrototypeKeys(internals.globalConfig);
    stripPrototypeKeys(internals.localConfig);

    const rawGlobal = internals.globalConfig;
    const rawLocal = internals.localConfig;
    const global = rawGlobal ? normalizeConfigShape(rawGlobal) : null;
    const local = rawLocal ? normalizeConfigShape(rawLocal) : null;
    this.shapeIssues = {
      global: global?.issues ?? [],
      local: local?.issues ?? [],
    };
    this.ignoredLocalKeys = [];
    internals.globalConfig = global?.config ?? null;
    internals.localConfig = local
      ? this.restrictLocal(local.config, global?.config ?? null)
      : null;
    try {
      this.cleaned = internals.merge();
    } finally {
      internals.globalConfig = rawGlobal;
      internals.localConfig = rawLocal;
    }
  }

  private restrictLocal(
    local: GuardrailsConfig,
    global: GuardrailsConfig | null,
  ): GuardrailsConfig {
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
    if (
      typeof internals.merge !== "function" ||
      !("globalConfig" in internals) ||
      !("localConfig" in internals) ||
      !("globalPath" in internals) ||
      !("localPath" in internals)
    ) {
      throw new Error(
        "[guardrails] pi-utils-settings ConfigLoader internals changed: update GuardedConfigLoader",
      );
    }
    return internals;
  }
}

function isFileSystemError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error;
}

const PROTOTYPE_KEYS = ["__proto__", "constructor", "prototype"];

/** Remove __proto__/constructor/prototype own keys, recursively, in place. */
function stripPrototypeKeys(value: unknown): void {
  if (!value || typeof value !== "object") return;
  for (const key of PROTOTYPE_KEYS) {
    if (Object.hasOwn(value, key)) {
      delete (value as Record<string, unknown>)[key];
    }
  }
  for (const child of Object.values(value)) stripPrototypeKeys(child);
}

/**
 * Run upstream's load/save, then restore Object.prototype exactly as it was.
 * pi-utils-settings' deepMerge copies a parsed `"__proto__"` key onto
 * Object.prototype. Restoring a snapshot undoes only what the merge changed,
 * and never deletes built-in members.
 */
async function withPrototypeGuard(run: () => Promise<void>): Promise<void> {
  const proto = Object.prototype as Record<string | symbol, unknown>;
  const before = new Map(
    Reflect.ownKeys(proto).map((key) => [
      key,
      Object.getOwnPropertyDescriptor(proto, key),
    ]),
  );
  try {
    await run();
  } finally {
    for (const key of Reflect.ownKeys(proto)) {
      if (!before.has(key)) delete proto[key];
    }
    for (const [key, descriptor] of before) {
      const now = Object.getOwnPropertyDescriptor(proto, key);
      if (
        descriptor &&
        (now?.value !== descriptor.value ||
          now?.get !== descriptor.get ||
          now?.set !== descriptor.set)
      ) {
        Object.defineProperty(proto, key, descriptor);
      }
    }
  }
}
