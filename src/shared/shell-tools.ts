import { resolveFromCwd } from "../core/paths/path";

/**
 * Tool registered by pi-interactive-shell. Raw `command` launches run a shell
 * command in a PTY, and text sent to an existing session can run one, so both
 * need the same checks as `bash`.
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
  /** True when the command is text submitted to an existing session. */
  sessionInput?: boolean;
}

/**
 * Return the shell command a tool call will execute, or undefined when the
 * call does not execute one.
 *
 * - `bash`: `input.command` in the session cwd.
 * - `interactive_shell`:
 *   - raw `command` launches; `input.cwd` is resolved against the session cwd.
 *   - text sent to an existing session (`input`, `inputPaste`, `inputHex`,
 *     literal `inputKeys`) once it is submitted (Enter, a newline, or
 *     `submit: true`). Unsubmitted text is buffered per session and checked
 *     together with the text that submits it.
 *   - structured `spawn` launches and session queries return undefined.
 *
 * Pass the tool call id so the per-session buffer advances exactly once per
 * call even though several guardrails features inspect the same call.
 */
export function shellCommandForTool(
  toolName: string,
  input: Record<string, unknown>,
  cwd: string,
  toolCallId?: string,
): ShellCommandInvocation | undefined {
  if (toolName === "bash") {
    return {
      command: String(input.command ?? ""),
      cwd,
      hasExplicitCwd: false,
    };
  }

  if (toolName !== INTERACTIVE_SHELL_TOOL) return undefined;

  if (typeof input.sessionId === "string" && input.sessionId) {
    const submitted = submittedSessionText(input, toolCallId);
    return submitted === undefined
      ? undefined
      : { command: submitted, cwd, hasExplicitCwd: false, sessionInput: true };
  }

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

// --- Session input -----------------------------------------------------------

/** Unsubmitted line text per interactive_shell session. */
const pendingLines = new Map<string, string>();
/** Results already computed for a tool call (bounded). */
const callResults = new Map<string, string | undefined>();
const MAX_CALL_RESULTS = 256;

/** Test hook. */
export function resetSessionInputState(): void {
  pendingLines.clear();
  callResults.clear();
}

const IGNORED_KEYS = new Set([
  "up",
  "down",
  "left",
  "right",
  "delete",
  "del",
  "dc",
  "insert",
  "ic",
  "home",
  "end",
  "pageup",
  "pgup",
  "ppage",
  "pagedown",
  "pgdn",
  "npage",
  ...Array.from({ length: 12 }, (_, i) => `f${i + 1}`),
  ...Array.from({ length: 10 }, (_, i) => `kp${i}`),
  "kp/",
  "kp*",
  "kp-",
  "kp+",
  "kp.",
]);

/**
 * Approximate the bytes pi-interactive-shell sends for one named key. Only
 * line-editing effects matter here; unknown tokens are sent literally by
 * interactive-shell, so they are treated as literal text.
 */
function keyBytes(token: string): string {
  let rest = token.trim().toLowerCase();
  if (!rest) return "";
  let ctrl = false;
  let alt = false;
  let shift = false;
  while (rest.length > 2) {
    const prefix = /^(ctrl[+-]|alt[+-]|shift[+-]|c-|m-|s-)/.exec(rest)?.[1];
    if (!prefix) break;
    if (prefix.startsWith("c")) ctrl = true;
    else if (prefix.startsWith("a") || prefix === "m-") alt = true;
    else shift = true;
    rest = rest.slice(prefix.length);
  }

  if (rest === "enter" || rest === "return" || rest === "kpenter") return "\r";
  if (rest === "backspace" || rest === "bspace") return "\x7f";
  if (rest === "space") return " ";
  if (rest === "tab" || rest === "btab") return "\t";
  if (rest === "escape" || rest === "esc") return "\x1b";
  if (IGNORED_KEYS.has(rest)) return "";

  if (rest.length === 1) {
    if (alt) return "";
    if (ctrl && /[a-z]/.test(rest)) {
      return String.fromCharCode(rest.charCodeAt(0) - 96);
    }
    return shift ? rest.toUpperCase() : rest;
  }

  // Unknown key name: interactive-shell sends the token literally.
  return token;
}

function hexBytes(values: unknown): string {
  if (!Array.isArray(values)) return "";
  let result = "";
  for (const raw of values) {
    const trimmed = String(raw).trim().toLowerCase();
    const normalized = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
    if (/^[0-9a-f]{1,2}$/.test(normalized)) {
      result += String.fromCharCode(Number.parseInt(normalized, 16));
    }
  }
  return result;
}

/** Bytes in the order pi-interactive-shell writes them: hex, text, paste, keys, submit. */
function sessionInputBytes(input: Record<string, unknown>): string {
  let bytes = hexBytes(input.inputHex);
  if (typeof input.input === "string") bytes += input.input;
  if (typeof input.inputPaste === "string") bytes += input.inputPaste;
  if (Array.isArray(input.inputKeys)) {
    for (const key of input.inputKeys) bytes += keyBytes(String(key));
  }
  if (input.submit === true) bytes += "\r";
  return bytes;
}

/**
 * Run the bytes through a minimal line editor. Returns the completed lines
 * and the text still pending on the current line.
 */
function editLines(
  pending: string,
  bytes: string,
): { lines: string[]; pending: string } {
  const lines: string[] = [];
  let line = pending;
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (ch === "\r" || ch === "\n") {
      lines.push(line);
      line = "";
    } else if (ch === "\x03" || ch === "\x15") {
      // Ctrl+C / Ctrl+U discard the line.
      line = "";
    } else if (ch === "\x7f" || ch === "\b") {
      line = line.slice(0, -1);
    } else if (ch === "\x17") {
      // Ctrl+W deletes the previous word.
      line = line.replace(/\S*\s*$/, "");
    } else if (ch === "\x1b") {
      // Skip escape sequences (CSI, SS3, or a single meta char).
      const next = bytes[i + 1];
      if (next === "[") {
        i += 2;
        while (i < bytes.length && !/[@-~]/.test(bytes[i])) i++;
      } else if (next === "O") {
        i += 2;
      } else {
        i += 1;
      }
    } else if (ch >= " " || ch === "\t") {
      line += ch;
    }
  }
  return { lines, pending: line };
}

function submittedSessionText(
  input: Record<string, unknown>,
  toolCallId: string | undefined,
): string | undefined {
  if (toolCallId && callResults.has(toolCallId)) {
    return callResults.get(toolCallId);
  }

  const sessionId = String(input.sessionId);
  const { lines, pending } = editLines(
    pendingLines.get(sessionId) ?? "",
    sessionInputBytes(input),
  );
  const submitted = lines.some((line) => line.trim())
    ? lines.join("\n")
    : undefined;

  // Without a call id, peek only: don't advance the session buffer.
  if (toolCallId) {
    if (pending) pendingLines.set(sessionId, pending);
    else pendingLines.delete(sessionId);
    callResults.set(toolCallId, submitted);
    if (callResults.size > MAX_CALL_RESULTS) {
      const oldest = callResults.keys().next().value;
      if (oldest !== undefined) callResults.delete(oldest);
    }
  }
  return submitted;
}
