import { beforeEach, describe, expect, it } from "vitest";
import {
  resetSessionInputState,
  settleSessionInput,
  shellCommandForTool,
} from "./shell-tools";

describe("shellCommandForTool", () => {
  it("returns bash commands in the session cwd", () => {
    expect(shellCommandForTool("bash", { command: "ls" }, "/repo")).toEqual({
      command: "ls",
      cwd: "/repo",
      hasExplicitCwd: false,
    });
  });

  it("returns interactive_shell raw commands", () => {
    expect(
      shellCommandForTool(
        "interactive_shell",
        { command: "npm test" },
        "/repo",
      ),
    ).toEqual({ command: "npm test", cwd: "/repo", hasExplicitCwd: false });
  });

  it("resolves an interactive_shell cwd against the session cwd", () => {
    expect(
      shellCommandForTool(
        "interactive_shell",
        { command: "make", cwd: "../other" },
        "/repo",
      ),
    ).toEqual({ command: "make", cwd: "/other", hasExplicitCwd: true });
  });

  it("ignores interactive_shell calls that do not launch a raw command", () => {
    for (const input of [
      { spawn: { agent: "pi", prompt: "dangerous-cmd" } },
      { sessionId: "calm-reef", kill: true },
      { listBackground: true },
      { command: "   " },
    ]) {
      expect(
        shellCommandForTool("interactive_shell", input, "/repo"),
      ).toBeUndefined();
    }
  });

  it("ignores unrelated tools", () => {
    expect(
      shellCommandForTool("custom", { command: "dangerous-cmd" }, "/repo"),
    ).toBeUndefined();
  });
});

describe("shellCommandForTool session input", () => {
  beforeEach(() => resetSessionInputState());

  let counter = 0;
  /** One tool call that runs (executed) or is blocked. */
  const send = (
    input: Record<string, unknown>,
    sessionId = "calm-reef",
    executed = true,
  ) => {
    const id = `call-${++counter}`;
    const command = shellCommandForTool(
      "interactive_shell",
      { sessionId, ...input },
      "/repo",
      id,
    )?.command;
    settleSessionInput(id, executed);
    return command;
  };

  it("returns submitted text", () => {
    expect(send({ input: "wipe build", submit: true })).toBe("wipe build");
    expect(send({ input: "ls\n" })).toBe("ls");
    expect(send({ inputPaste: "a\nb\n" })).toBe("a\nb");
    expect(send({ input: "make", inputKeys: ["enter"] })).toBe("make");
    expect(send({ inputHex: ["0x6c", "0x73", "0x0d"] })).toBe("ls");
  });

  it("buffers unsubmitted text per session until it is submitted", () => {
    expect(send({ input: "wipe " })).toBeUndefined();
    expect(send({ input: "other", submit: true }, "other-session")).toBe(
      "other",
    );
    expect(send({ input: "home" })).toBeUndefined();
    expect(send({ inputKeys: ["enter"] })).toBe("wipe home");
    expect(send({ inputKeys: ["enter"] })).toBeUndefined();
  });

  it("treats unknown key tokens as literal text, like interactive-shell", () => {
    expect(send({ inputKeys: ["wipe home", "enter"] })).toBe("wipe home");
    expect(send({ inputKeys: ["l", "s", "ctrl+m"] })).toBe("ls");
  });

  it("applies basic line editing", () => {
    expect(send({ input: "wipe home", inputKeys: ["ctrl+c"] })).toBeUndefined();
    expect(send({ input: "ls", submit: true })).toBe("ls");
    expect(send({ input: "lss", inputKeys: ["backspace", "enter"] })).toBe(
      "ls",
    );
    expect(send({ input: "ls", inputKeys: ["left", "up", "enter"] })).toBe(
      "ls",
    );
  });

  it("advances the buffer once per tool call id", () => {
    const input = { sessionId: "calm-reef", input: "wipe " };
    for (let i = 0; i < 3; i++) {
      shellCommandForTool("interactive_shell", input, "/repo", "same-call");
    }
    settleSessionInput("same-call", true);
    settleSessionInput("same-call", true);
    expect(send({ input: "home", submit: true })).toBe("wipe home");
  });

  it("keeps the typed prefix when the submitting call is blocked", () => {
    expect(send({ input: "wipe " })).toBeUndefined();
    // Blocked: nothing was sent, so the terminal line still holds "wipe ".
    expect(
      send({ input: "home", inputKeys: ["enter"] }, "calm-reef", false),
    ).toBe("wipe home");
    expect(send({ input: "echo ok", submit: true })).toBe("wipe echo ok");
  });

  it("does not advance the buffer for a blocked unsubmitted call", () => {
    expect(send({ input: "wipe " }, "calm-reef", false)).toBeUndefined();
    expect(send({ input: "ls", submit: true })).toBe("ls");
  });

  it("peeks without advancing when no tool call id is given", () => {
    expect(
      shellCommandForTool(
        "interactive_shell",
        { sessionId: "calm-reef", input: "wipe " },
        "/repo",
      ),
    ).toBeUndefined();
    expect(send({ input: "ls", submit: true })).toBe("ls");
  });

  it("ignores blank submissions", () => {
    expect(send({ inputKeys: ["enter"] })).toBeUndefined();
    expect(send({ input: "   ", submit: true })).toBeUndefined();
  });
});
