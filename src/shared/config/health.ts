import { existsSync, readFileSync, statSync } from "node:fs";
import { lstat, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import type { GuardrailsConfig } from "./types";

/**
 * Health of one on-disk config file.
 *
 * - `absent`: nothing at the path. Running on defaults is expected.
 * - `ok`: the file parsed as a JSON object.
 * - `broken`: something is at the path but it can't be used: a dangling
 *   symlink (e.g. its volume is unmounted), a permission error, or invalid
 *   JSON. The upstream loader treats all of these like `absent`, which
 *   silently drops every custom rule.
 */
export type ConfigFileState =
  | { state: "absent"; path: string }
  | { state: "ok"; path: string }
  | { state: "broken"; path: string; reason: string };

/**
 * How the global scope is being enforced after a load.
 *
 * - `normal`: the global file loaded (or is absent).
 * - `snapshot`: the global file is broken; the last good copy is in use.
 * - `fail-closed`: the global file is broken and no snapshot exists; every
 *   shell command needs confirmation.
 */
export type GlobalConfigMode = "normal" | "snapshot" | "fail-closed";

export interface ConfigHealth {
  mode: GlobalConfigMode;
  global: ConfigFileState;
  local: ConfigFileState;
  /** ISO timestamp of the snapshot in use when mode is `snapshot`. */
  snapshotSavedAt?: string;
  /** Local (project) keys ignored because they would weaken protection. */
  ignoredLocalKeys: string[];
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** Classify a config path without trusting the loader's catch-all read. */
export async function probeConfigFile(path: string): Promise<ConfigFileState> {
  try {
    await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
      return { state: "absent", path };
    }
    return { state: "broken", path, reason: `cannot stat: ${String(error)}` };
  }

  try {
    await stat(path);
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOENT" || code === "ENOTDIR") {
      return {
        state: "broken",
        path,
        reason: "dangling symlink (target missing; is its volume mounted?)",
      };
    }
    return { state: "broken", path, reason: `cannot stat: ${String(error)}` };
  }

  let content: string;
  try {
    content = await readFile(path, "utf-8");
  } catch (error) {
    return { state: "broken", path, reason: `cannot read: ${String(error)}` };
  }

  try {
    const parsed: unknown = JSON.parse(content);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { state: "broken", path, reason: "not a JSON object" };
    }
  } catch (error) {
    return {
      state: "broken",
      path,
      reason: `invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  return { state: "ok", path };
}

/** Same path the settings loader uses for the global scope. */
export function globalConfigPath(): string {
  return resolve(getAgentDir(), "extensions/guardrails.json");
}

/**
 * Same lookup the settings loader uses for the local scope: the nearest
 * `.pi` directory above cwd, stopping at home.
 */
export function localConfigPath(cwd = process.cwd()): string | null {
  let dir = cwd;
  const home = homedir();
  while (dir !== home) {
    const piDir = resolve(dir, ".pi");
    if (existsSync(piDir) && statSync(piDir).isDirectory()) {
      return resolve(piDir, "extensions/guardrails.json");
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/**
 * Guardrails state lives outside the extension config directory so it
 * never dirties a shared checkout that provides `extensions/`.
 */
export function guardrailsStateDir(): string {
  return resolve(getAgentDir(), "state/guardrails");
}

function snapshotPath(): string {
  return resolve(guardrailsStateDir(), "last-good-global.json");
}

interface Snapshot {
  savedAt: string;
  sourcePath: string;
  config: GuardrailsConfig;
}

export async function readGlobalSnapshot(): Promise<Snapshot | null> {
  try {
    const parsed = JSON.parse(await readFile(snapshotPath(), "utf-8"));
    if (parsed && typeof parsed === "object" && parsed.config) {
      return parsed as Snapshot;
    }
  } catch {
    // No usable snapshot.
  }
  return null;
}

/** Store the last global config that loaded cleanly. Best effort. */
export async function writeGlobalSnapshot(
  config: GuardrailsConfig,
  sourcePath: string,
): Promise<void> {
  const path = snapshotPath();
  try {
    const existing = await readGlobalSnapshot();
    if (
      existing &&
      JSON.stringify(existing.config) === JSON.stringify(config)
    ) {
      return;
    }
    await mkdir(dirname(path), { recursive: true });
    const snapshot: Snapshot = {
      savedAt: new Date().toISOString(),
      sourcePath,
      config,
    };
    await writeFile(path, `${JSON.stringify(snapshot, null, 2)}\n`, "utf-8");
  } catch (error) {
    console.error(`[guardrails] Failed to write config snapshot: ${error}`);
  }
}

// --- Trusted project grants -------------------------------------------------

/**
 * "Allow for project" grants are stored here, keyed by project root, instead
 * of in the project's own `.pi/extensions/guardrails.json`. Anything inside
 * the project (including the agent) can write that file, so its
 * `allowedPatterns` are ignored.
 */
function projectGrantsPath(): string {
  return resolve(guardrailsStateDir(), "project-grants.json");
}

type ProjectGrants = Record<string, { pattern: string; regex?: boolean }[]>;

/** Project key: the directory holding `.pi`, else cwd. */
export function projectKey(cwd = process.cwd()): string {
  const local = localConfigPath(cwd);
  return local ? dirname(dirname(dirname(local))) : resolve(cwd);
}

function readProjectGrantsSync(): ProjectGrants {
  try {
    const parsed = JSON.parse(readFileSync(projectGrantsPath(), "utf-8"));
    return parsed && typeof parsed === "object"
      ? (parsed as ProjectGrants)
      : {};
  } catch {
    return {};
  }
}

export function trustedProjectGrants(
  key = projectKey(),
): { pattern: string; regex?: boolean }[] {
  const grants = readProjectGrantsSync()[key];
  return Array.isArray(grants) ? grants : [];
}

export async function addTrustedProjectGrant(
  pattern: { pattern: string; regex?: boolean },
  key = projectKey(),
): Promise<void> {
  const all = readProjectGrantsSync();
  const existing = Array.isArray(all[key]) ? all[key] : [];
  if (!existing.some((entry) => entry.pattern === pattern.pattern)) {
    all[key] = [...existing, pattern];
  }
  const path = projectGrantsPath();
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(all, null, 2)}\n`, "utf-8");
}
