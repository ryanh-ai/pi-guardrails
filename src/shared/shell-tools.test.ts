import { describe, expect, it } from "vitest";
import { shellCommandForTool } from "./shell-tools";

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
      { sessionId: "calm-reef", input: "dangerous-cmd", submit: true },
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
