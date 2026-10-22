import type {
  BashToolCallEvent,
  ExtensionAPI,
  ExtensionContext,
  ExtensionHandler,
  ReadToolCallEvent,
  ToolCallEvent,
  ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import {
  createMock,
  type DeepMocked,
  type PartialFuncReturn,
} from "@golevelup/ts-vitest";
import { assert, beforeEach, describe, expect, it, vi } from "vitest";
import { addTrustedProjectGrant, configLoader } from "../../src/shared/config";
import {
  GUARDRAILS_ACTION_BLOCKED_EVENT,
  GUARDRAILS_FEATURE_REGISTER_EVENT,
  GUARDRAILS_FEATURE_REQUEST_EVENT,
  GUARDRAILS_PROMPT_CLOSED_EVENT,
  GUARDRAILS_PROMPT_OPENED_EVENT,
  type GuardrailsPromptOpenedPayload,
} from "../../src/shared/events";
import permissionGate from "./index";

// Control the config the hook sees without touching the real config loader.
vi.mock("../../src/shared/config", () => {
  function makeConfig(overrides: Record<string, unknown> = {}) {
    return {
      enabled: true,
      features: { permissionGate: true, policies: true, pathAccess: true },
      permissionGate: {
        patterns: [{ pattern: "dangerous-cmd", description: "test danger" }],
        useBuiltinMatchers: false,
        requireConfirmation: true,
        allowedPatterns: [],
        autoDenyPatterns: [],
        ...overrides,
      },
    };
  }

  return {
    configLoader: {
      load: vi.fn().mockResolvedValue(undefined),
      getConfig: vi.fn(() => makeConfig()),
      getRawConfig: vi.fn(() => null),
      save: vi.fn().mockResolvedValue(undefined),
      getHealth: vi.fn(() => ({
        mode: "normal",
        global: { state: "ok", path: "/agent/extensions/guardrails.json" },
        local: { state: "absent", path: "" },
        ignoredLocalKeys: [],
      })),
    },
    addTrustedProjectGrant: vi.fn().mockResolvedValue(undefined),
  };
});

type ToolCallHandler = ExtensionHandler<ToolCallEvent, ToolCallEventResult>;

function registeredToolCallHandler(pi: DeepMocked<ExtensionAPI>) {
  const calls: unknown[][] = pi.on.mock.calls;
  return calls.find(([event]) => event === "tool_call")?.[1] as
    | ToolCallHandler
    | undefined;
}

function createCtx(overrides: PartialFuncReturn<ExtensionContext> = {}) {
  return createMock<ExtensionContext>({
    hasUI: true,
    mode: "tui",
    ui: {
      custom: vi.fn().mockResolvedValue(undefined),
      select: vi.fn().mockResolvedValue(undefined),
      notify: vi.fn(),
    },
    abort: vi.fn(),
    ...overrides,
  });
}

const DANGEROUS_EVENT = {
  type: "tool_call",
  toolCallId: "dangerous-call",
  toolName: "bash",
  input: { command: "dangerous-cmd" },
} satisfies BashToolCallEvent;

describe("permissionGate extension hook", () => {
  let pi: DeepMocked<ExtensionAPI>;
  let toolCallHandler: ToolCallHandler | undefined;

  beforeEach(async () => {
    vi.clearAllMocks();
    pi = createMock<ExtensionAPI>();
    await permissionGate(pi);
    toolCallHandler = registeredToolCallHandler(pi);
  });

  it("registers the permissionGate feature on request", async () => {
    const registration = pi.events.on.mock.calls.find(
      ([event]) => event === GUARDRAILS_FEATURE_REQUEST_EVENT,
    );

    assert(registration, "feature request handler should be registered");
    registration[1](undefined);
    expect(pi.events.emit).toHaveBeenCalledWith(
      GUARDRAILS_FEATURE_REGISTER_EVENT,
      expect.objectContaining({
        feature: { id: "permissionGate" },
      }),
    );
  });

  it("returns undefined for safe commands", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const result = await toolCallHandler(
      {
        type: "tool_call",
        toolCallId: "safe-call",
        toolName: "bash",
        input: { command: "echo hello" },
      } satisfies BashToolCallEvent,
      createCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("returns undefined for non-bash tools", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const result = await toolCallHandler(
      {
        type: "tool_call",
        toolCallId: "read-call",
        toolName: "read",
        input: { path: "dangerous-cmd" },
      } satisfies ReadToolCallEvent,
      createCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("deny returns { block: true } without aborting the turn", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue("deny"), select: vi.fn() },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(result).toEqual({
      block: true,
      reason: "User denied dangerous command",
    });
    expect(ctx.abort).not.toHaveBeenCalled();
    expect(pi.events.emit).toHaveBeenCalledWith(
      GUARDRAILS_ACTION_BLOCKED_EVENT,
      expect.objectContaining({
        block: expect.objectContaining({ source: "user" }),
      }),
    );
  });

  it("stop calls ctx.abort() and returns { block: true } with user-stop source", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue("stop"), select: vi.fn() },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(result).toEqual({
      block: true,
      reason: "User declined and stopped dangerous command",
    });
    expect(ctx.abort).toHaveBeenCalledTimes(1);
    expect(pi.events.emit).toHaveBeenCalledWith(
      GUARDRAILS_ACTION_BLOCKED_EVENT,
      expect.objectContaining({
        block: expect.objectContaining({ source: "user-stop" }),
      }),
    );
  });

  it("allow once returns undefined and does not abort", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue("allow"), select: vi.fn() },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);
    expect(result).toBeUndefined();
    expect(ctx.abort).not.toHaveBeenCalled();

    const opened = pi.events.emit.mock.calls.find(
      ([event]) => event === GUARDRAILS_PROMPT_OPENED_EVENT,
    )?.[1] as GuardrailsPromptOpenedPayload | undefined;
    assert(opened, "prompt opened event should be emitted");
    expect(pi).toHaveEmitted(
      GUARDRAILS_PROMPT_CLOSED_EVENT,
      expect.objectContaining({ prompt: { id: opened.prompt.id } }),
    );
  });

  it("allow for project saves an exact command grant to the trusted project store after the scope prompt", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    vi.mocked(configLoader.getRawConfig).mockReturnValueOnce({
      permissionGate: { allowedPatterns: [{ pattern: "existing" }] },
    });
    const select = vi.fn((_prompt: string, options: string[]) =>
      Promise.resolve(options[0]),
    );
    const ctx = createCtx({
      ui: {
        custom: vi.fn().mockResolvedValue("allow-project"),
        notify: vi.fn(),
        select,
      },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(result).toBeUndefined();
    expect(select).toHaveBeenCalledWith(
      "What should be allowed?",
      expect.arrayContaining([
        expect.stringContaining("This exact command"),
        expect.stringContaining("All commands matching"),
        "Cancel (allow once without saving)",
      ]),
    );
    // Never written to the project's own config: the agent can edit that file.
    expect(configLoader.save).not.toHaveBeenCalledWith(
      "local",
      expect.anything(),
    );
    expect(addTrustedProjectGrant).toHaveBeenCalledWith({
      pattern: "dangerous-cmd",
    });
    // Mirrored into memory so it applies right away.
    expect(configLoader.save).toHaveBeenCalledWith(
      "memory",
      expect.objectContaining({
        permissionGate: expect.objectContaining({
          allowedPatterns: [
            { pattern: "existing" },
            { pattern: "dangerous-cmd" },
          ],
        }),
      }),
    );

    const openedIndex = pi.events.emit.mock.calls.findIndex(
      ([event]) => event === GUARDRAILS_PROMPT_OPENED_EVENT,
    );
    const closedIndex = pi.events.emit.mock.calls.findIndex(
      ([event]) => event === GUARDRAILS_PROMPT_CLOSED_EVENT,
    );
    expect(openedIndex).toBeGreaterThanOrEqual(0);
    expect(closedIndex).toBeGreaterThan(openedIndex);
    expect(pi.events.emit.mock.invocationCallOrder[openedIndex]).toBeLessThan(
      select.mock.invocationCallOrder[0],
    );
    expect(
      pi.events.emit.mock.invocationCallOrder[closedIndex],
    ).toBeGreaterThan(select.mock.invocationCallOrder[0]);
  });

  it("allow globally can save the matching command class to global config", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const select = vi.fn((_prompt: string, options: string[]) =>
      Promise.resolve(options[1]),
    );
    const ctx = createCtx({
      ui: {
        custom: vi.fn().mockResolvedValue("allow-global"),
        notify: vi.fn(),
        select,
      },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(result).toBeUndefined();
    expect(configLoader.save).toHaveBeenCalledWith(
      "global",
      expect.objectContaining({
        permissionGate: expect.objectContaining({
          allowedPatterns: [
            { pattern: "dangerous-cmd", description: "test danger" },
          ],
        }),
      }),
    );
  });

  it("closes the prompt when its UI throws", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({
      ui: {
        custom: vi.fn().mockRejectedValue(new Error("UI failed")),
        select: vi.fn(),
      },
    });

    await expect(toolCallHandler(DANGEROUS_EVENT, ctx)).rejects.toThrow(
      "UI failed",
    );

    const opened = pi.events.emit.mock.calls.find(
      ([event]) => event === GUARDRAILS_PROMPT_OPENED_EVENT,
    )?.[1] as GuardrailsPromptOpenedPayload | undefined;
    assert(opened, "prompt opened event should be emitted");
    expect(pi).toHaveEmitted(
      GUARDRAILS_PROMPT_CLOSED_EVENT,
      expect.objectContaining({ prompt: { id: opened.prompt.id } }),
    );
  });

  it("RPC fallback exposes 'Decline and stop' and maps it to stop", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const select = vi.fn().mockResolvedValue("Decline and stop");
    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue(undefined), select },
    });

    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(select).toHaveBeenCalledWith(
      expect.stringContaining("test danger"),
      expect.arrayContaining([
        "Allow once",
        "Allow for session",
        "Deny",
        "Decline and stop",
      ]),
    );
    expect(result).toEqual({
      block: true,
      reason: "User declined and stopped dangerous command",
    });
    expect(ctx.abort).toHaveBeenCalledTimes(1);
  });

  it("RPC fallback title shows the command, indented on every line", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const select = vi.fn().mockResolvedValue("Deny");
    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue(undefined), select },
    });

    await toolCallHandler(
      { ...DANGEROUS_EVENT, input: { command: "dangerous-cmd \\\n  --force" } },
      ctx,
    );

    const [title] = select.mock.calls[0] ?? [];
    expect(title).toBe(
      "Dangerous command: test danger\n\n    dangerous-cmd \\\n      --force",
    );
  });

  it("non-interactive (no UI) blocks with nonInteractive source and does not abort", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({ hasUI: false });
    const result = await toolCallHandler(DANGEROUS_EVENT, ctx);

    expect(result).toEqual({
      block: true,
      reason: expect.stringContaining("no UI to confirm"),
    });
    expect(ctx.abort).not.toHaveBeenCalled();
    expect(pi.events.emit).toHaveBeenCalledWith(
      GUARDRAILS_ACTION_BLOCKED_EVENT,
      expect.objectContaining({
        block: expect.objectContaining({ source: "nonInteractive" }),
      }),
    );
  });

  it("gates dangerous interactive_shell raw commands", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx({
      ui: { custom: vi.fn().mockResolvedValue("deny"), select: vi.fn() },
    });
    const result = await toolCallHandler(
      {
        type: "tool_call",
        toolCallId: "shell-call",
        toolName: "interactive_shell",
        input: { command: "dangerous-cmd", mode: "dispatch" },
      } as ToolCallEvent,
      ctx,
    );

    expect(result).toEqual({
      block: true,
      reason: "User denied dangerous command",
    });
    expect(pi.events.emit).toHaveBeenCalledWith(
      GUARDRAILS_ACTION_BLOCKED_EVENT,
      expect.objectContaining({
        action: expect.objectContaining({ origin: "interactive_shell" }),
        context: expect.objectContaining({ toolName: "interactive_shell" }),
      }),
    );
  });

  it("ignores interactive_shell calls without a raw command", async () => {
    assert(toolCallHandler, "tool_call handler should be registered");

    const ctx = createCtx();
    for (const input of [
      { spawn: { agent: "pi", prompt: "dangerous-cmd" } },
      { sessionId: "calm-reef", input: "dangerous-cmd" },
    ]) {
      const result = await toolCallHandler(
        {
          type: "tool_call",
          toolCallId: "shell-call",
          toolName: "interactive_shell",
          input,
        } as ToolCallEvent,
        ctx,
      );
      expect(result).toBeUndefined();
    }
    expect(ctx.ui.custom).not.toHaveBeenCalled();
  });

  describe("ordering and config health", () => {
    function config(permissionGate: Record<string, unknown>) {
      return {
        enabled: true,
        features: { permissionGate: true, policies: true, pathAccess: false },
        permissionGate: {
          patterns: [{ pattern: "dangerous-cmd", description: "test danger" }],
          useBuiltinMatchers: false,
          requireConfirmation: true,
          allowedPatterns: [],
          autoDenyPatterns: [],
          ...permissionGate,
        },
      } as unknown as ReturnType<typeof configLoader.getConfig>;
    }

    function bash(command: string, id = "order-call"): BashToolCallEvent {
      return {
        type: "tool_call",
        toolCallId: id,
        toolName: "bash",
        input: { command },
      };
    }

    it("auto-deny wins over a matching allowed pattern", async () => {
      assert(toolCallHandler, "tool_call handler should be registered");
      vi.mocked(configLoader.getConfig).mockReturnValue(
        config({
          allowedPatterns: [{ pattern: "\\bgit\\s+status", regex: true }],
          autoDenyPatterns: [{ pattern: "wipe-everything" }],
        }),
      );

      const ctx = createCtx();
      const blocked = await toolCallHandler(
        bash("git status && wipe-everything"),
        ctx,
      );
      expect(blocked).toEqual({
        block: true,
        reason:
          "Command matched auto-deny pattern and was blocked automatically.",
      });

      const allowed = await toolCallHandler(bash("git status"), ctx);
      expect(allowed).toBeUndefined();
      expect(ctx.ui.custom).not.toHaveBeenCalled();
    });

    it("an allowed pattern still skips the confirmation prompt", async () => {
      assert(toolCallHandler, "tool_call handler should be registered");
      vi.mocked(configLoader.getConfig).mockReturnValue(
        config({ allowedPatterns: [{ pattern: "dangerous-cmd" }] }),
      );

      const ctx = createCtx();
      expect(await toolCallHandler(bash("dangerous-cmd"), ctx)).toBeUndefined();
      expect(ctx.ui.custom).not.toHaveBeenCalled();
    });

    it("fail-closed mode confirms every shell command", async () => {
      assert(toolCallHandler, "tool_call handler should be registered");
      vi.mocked(configLoader.getHealth).mockReturnValue({
        mode: "fail-closed",
        global: {
          state: "broken",
          path: "/agent/extensions/guardrails.json",
          reason: "dangling symlink",
        },
        local: { state: "absent", path: "" },
        ignoredLocalKeys: [],
      });

      const ctx = createCtx({
        ui: { custom: vi.fn().mockResolvedValue("deny"), select: vi.fn() },
      });
      const result = await toolCallHandler(bash("echo hello"), ctx);
      expect(result).toEqual({
        block: true,
        reason: "User denied dangerous command",
      });
      expect(ctx.ui.custom).toHaveBeenCalled();

      const headless = await toolCallHandler(
        bash("echo hello"),
        createCtx({ hasUI: false }),
      );
      expect(headless).toMatchObject({ block: true });
      expect((headless as { reason: string }).reason).toContain(
        "guardrails config unreadable (dangling symlink)",
      );
    });

    it("allows once and reports the error when saving a grant fails", async () => {
      assert(toolCallHandler, "tool_call handler should be registered");
      vi.mocked(configLoader.save).mockRejectedValueOnce(
        new Error("Refusing to overwrite /agent/extensions/guardrails.json"),
      );
      const notify = vi.fn();
      const ctx = createCtx({
        ui: {
          custom: vi.fn().mockResolvedValue("allow-global"),
          select: vi.fn((_prompt: string, options: string[]) =>
            Promise.resolve(options[0]),
          ),
          notify,
        },
      });

      const result = await toolCallHandler(DANGEROUS_EVENT, ctx);
      expect(result).toBeUndefined();
      expect(notify).toHaveBeenCalledWith(
        expect.stringContaining("grant not saved: Refusing to overwrite"),
        "error",
      );
    });

    it("checks text submitted to an existing interactive_shell session", async () => {
      assert(toolCallHandler, "tool_call handler should be registered");
      vi.mocked(configLoader.getConfig).mockReturnValue(
        config({ autoDenyPatterns: [{ pattern: "wipe-everything" }] }),
      );
      const ctx = createCtx();
      const event = (id: string, input: Record<string, unknown>) =>
        ({
          type: "tool_call",
          toolCallId: id,
          toolName: "interactive_shell",
          input: { sessionId: "gate-session", ...input },
        }) as ToolCallEvent;

      // Typed without submitting: allowed, and buffered once it has run.
      expect(
        await toolCallHandler(event("type-1", { input: "wipe-" }), ctx),
      ).toBeUndefined();
      const calls: unknown[][] = pi.on.mock.calls;
      const onEnd = calls.find(
        ([name]) => name === "tool_execution_end",
      )?.[1] as (event: unknown) => void;
      onEnd({
        toolCallId: "type-1",
        toolName: "interactive_shell",
        isError: false,
      });
      // Enter submits the buffered line.
      expect(
        await toolCallHandler(
          event("type-2", { input: "everything", inputKeys: ["enter"] }),
          ctx,
        ),
      ).toMatchObject({ block: true });
    });
  });
});
