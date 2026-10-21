import { resolveFromCwd } from "../core/paths/path";

/**
 * Tool registered by pi-interactive-shell. Raw `command` launches run a shell
 * command in a PTY, so they need the same checks as `bash`.
 */
export const INTERACTIVE_SHELL_TOOL = "interactive_shell";

/** Tools whose input can carry a shell command string. */
export const SHELL_COMMAND_TOOLS: ReadonlySet<string> = new Set([
  "bash",
  INTERACTIVE_SHELL_TOOL,
]);

export interface ShellCommandInvocation {
  command: string;
  /** Absolute directory the command will run in. */
  cwd: string;
  /** True when the tool input set an explicit working directory. */
  hasExplicitCwd: boolean;
}

/**
 * Return the shell command a tool call will execute, or undefined when the
 * call does not execute one.
 *
 * - `bash`: `input.command` in the session cwd.
 * - `interactive_shell`: only raw `command` launches. Structured `spawn`
 *   launches, session queries, and input sent to existing sessions return
 *   undefined. `input.cwd` is resolved against the session cwd.
 */
export function shellCommandForTool(
  toolName: string,
  input: Record<string, unknown>,
  cwd: string,
): ShellCommandInvocation | undefined {
  if (toolName === "bash") {
    return {
      command: String(input.command ?? ""),
      cwd,
      hasExplicitCwd: false,
    };
  }

  if (toolName !== INTERACTIVE_SHELL_TOOL) return undefined;
  if (typeof input.command !== "string" || !input.command.trim()) {
    return undefined;
  }

  const rawCwd = typeof input.cwd === "string" ? input.cwd.trim() : "";
  return {
    command: input.command,
    cwd: rawCwd ? resolveFromCwd(rawCwd, cwd) : cwd,
    hasExplicitCwd: rawCwd !== "",
  };
}
