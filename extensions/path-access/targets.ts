import { resolveFromCwd } from "../../src/core/paths";
import { extractBashPathCandidates } from "../../src/shared/paths";
import { shellCommandForTool } from "../../src/shared/shell-tools";

export async function targetsForTool(
  toolName: string,
  input: Record<string, unknown>,
  cwd: string,
): Promise<string[]> {
  if (["read", "write", "edit", "grep", "find", "ls"].includes(toolName)) {
    const raw = String(input.file_path ?? input.path ?? "").trim();
    return raw ? [resolveFromCwd(raw, cwd)] : [];
  }

  const invocation = shellCommandForTool(toolName, input, cwd);
  if (!invocation) return [];

  const candidates = await extractBashPathCandidates(
    invocation.command,
    invocation.cwd,
  );
  // An explicit interactive_shell cwd is itself an access target: the command
  // runs there even if it never names a path.
  return invocation.hasExplicitCwd
    ? [invocation.cwd, ...candidates]
    : candidates;
}
