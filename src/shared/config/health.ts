import { lstat, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * Health of one settings file.
 *
 * - `absent`: nothing at the path (or an empty file). Running on defaults is
 *   expected.
 * - `ok`: the file reads and parses as a JSON object.
 * - `broken`: something is at the path but can't be used, for example a
 *   dangling symlink (its volume is unmounted), a permission error, or
 *   invalid JSON. The settings loader treats all of these like `absent`, so
 *   without this check every custom rule would silently disappear.
 */
export type ConfigFileState =
  | { state: "absent"; path: string }
  | { state: "ok"; path: string }
  | { state: "broken"; path: string; reason: string };

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** A dangling symlink among the path's ancestors (e.g. a linked directory). */
async function danglingAncestor(path: string): Promise<string | undefined> {
  let dir = dirname(path);
  while (true) {
    try {
      const info = await lstat(dir);
      if (info.isSymbolicLink()) {
        try {
          await stat(dir);
        } catch {
          return dir;
        }
      }
    } catch {
      // Missing ancestor: keep walking up to find a dangling link above it.
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** Classify a settings file without trusting the loader's catch-all read. */
export async function probeConfigFile(path: string): Promise<ConfigFileState> {
  try {
    await lstat(path);
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOENT" || code === "ENOTDIR") {
      const link = await danglingAncestor(path);
      return link
        ? {
            state: "broken",
            path,
            reason: `dangling symlink ${link} (is its volume mounted?)`,
          }
        : { state: "absent", path };
    }
    return { state: "broken", path, reason: `cannot stat: ${String(error)}` };
  }

  try {
    await stat(path);
  } catch (error) {
    const code = errorCode(error);
    return code === "ENOENT" || code === "ENOTDIR"
      ? {
          state: "broken",
          path,
          reason: "dangling symlink (is its volume mounted?)",
        }
      : { state: "broken", path, reason: `cannot stat: ${String(error)}` };
  }

  let content: string;
  try {
    content = await readFile(path, "utf-8");
  } catch (error) {
    return { state: "broken", path, reason: `cannot read: ${String(error)}` };
  }
  // An empty file holds nothing to lose; treat it like a missing one.
  if (!content.trim()) return { state: "absent", path };
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
