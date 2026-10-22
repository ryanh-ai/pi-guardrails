import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Rule } from "../../src/core";
import { checkAction } from "../../src/core";
import type { ConfigHealth, PatternConfig } from "../../src/shared/config";
import { configLoader } from "../../src/shared/config";
import {
  createFeatureRegisterPayload,
  createPromptClosedPayload,
  createPromptOpenedPayload,
  emitActionBlocked,
  emitRiskDetected,
  GUARDRAILS_FEATURE_REGISTER_EVENT,
  GUARDRAILS_FEATURE_REQUEST_EVENT,
  GUARDRAILS_PROMPT_CLOSED_EVENT,
  GUARDRAILS_PROMPT_OPENED_EVENT,
  setupLegacyPromptEventAlias,
} from "../../src/shared/events";
import { shellCommandForTool } from "../../src/shared/shell-tools";
import {
  isCommandAllowed,
  type PersistentPermissionGateScope,
  saveCommandPersistentGrant,
  saveCommandSessionGrant,
} from "./grants";
import {
  createPermissionGateConfirmComponent,
  type PermissionGateConfirmResult,
} from "./prompt";
import type { PermissionGateMeta } from "./rules";
import {
  createPermissionGateRule,
  formatAutoDenyReason,
  matchCommandPattern,
} from "./rules";

type ScopedGrantChoice = "exact" | "class" | "cancel";

/**
 * While the global config is unreadable and no snapshot exists, every shell
 * command needs confirmation (and is blocked without a UI).
 */
function createFailClosedRule(health: ConfigHealth): Rule<PermissionGateMeta> {
  const reason =
    health.global.state === "broken"
      ? `guardrails config unreadable (${health.global.reason}); confirming every shell command`
      : "guardrails config unreadable; confirming every shell command";
  return {
    key: "permission-gate.fail-closed",
    check(action) {
      if (action.kind !== "command") return { kind: "pass" };
      return {
        kind: "match",
        reason,
        metadata: {
          command: action.command,
          description: reason,
          pattern: "(structural)",
        },
      };
    },
  };
}

interface ScopedGrantPromptContext {
  ui: {
    select(prompt: string, options: string[]): Promise<string | undefined>;
  };
}

function createScopedGrantPattern(
  command: string,
  matchedPattern: string,
  choice: Exclude<ScopedGrantChoice, "cancel">,
  configuredPatterns: PatternConfig[],
): PatternConfig {
  if (choice === "exact") return { pattern: command };

  const configured = configuredPatterns.find(
    (pattern) => pattern.pattern === matchedPattern,
  );
  if (configured) {
    return {
      pattern: configured.pattern,
      ...(configured.regex === undefined ? {} : { regex: configured.regex }),
      ...(configured.description === undefined
        ? {}
        : { description: configured.description }),
    };
  }

  return { pattern: matchedPattern, regex: true };
}

async function chooseScopedGrantPattern(
  ctx: ScopedGrantPromptContext,
  command: string,
  matchedPattern: string,
): Promise<ScopedGrantChoice> {
  if (matchedPattern === "(structural)") return "exact";

  const commandPreview =
    command.length > 80 ? `${command.slice(0, 77)}...` : command;
  const classPreview =
    matchedPattern.length > 80
      ? `${matchedPattern.slice(0, 77)}...`
      : matchedPattern;
  const exact = `This exact command: ${commandPreview}`;
  const commandClass = `All commands matching: ${classPreview}`;
  const cancel = "Cancel (allow once without saving)";

  const selection = await ctx.ui.select("What should be allowed?", [
    exact,
    commandClass,
    cancel,
  ]);

  if (selection === commandClass) return "class";
  if (selection === exact) return "exact";
  return "cancel";
}

export default async function permissionGate(pi: ExtensionAPI) {
  await configLoader.load();

  pi.events.on(GUARDRAILS_FEATURE_REQUEST_EVENT, () => {
    pi.events.emit(
      GUARDRAILS_FEATURE_REGISTER_EVENT,
      createFeatureRegisterPayload("permissionGate"),
    );
  });
  setupLegacyPromptEventAlias(pi, "permissionGate");

  pi.on("tool_call", async (event, ctx) => {
    const config = configLoader.getConfig();
    if (!config.enabled || !config.features.permissionGate) return;
    const invocation = shellCommandForTool(
      event.toolName,
      event.input as Record<string, unknown>,
      ctx.cwd,
      event.toolCallId,
    );
    if (!invocation) return;

    const { command } = invocation;
    const toolName = event.toolName;
    const action = { kind: "command" as const, command, origin: toolName };

    // Auto-deny always wins: allowed patterns and saved grants only skip the
    // confirmation prompt. Otherwise a broad or unanchored allow rule (or a
    // saved "all commands matching X" grant) would also bypass auto-deny.
    const autoDenyMatch = matchCommandPattern(
      command,
      config.permissionGate.autoDenyPatterns,
    );

    if (autoDenyMatch) {
      const reason = formatAutoDenyReason(autoDenyMatch);

      emitActionBlocked(pi, {
        feature: "permissionGate",
        action,
        reason,
        block: { source: "permission", metadata: autoDenyMatch },
        context: { toolName, input: event.input },
      });

      return { block: true, reason };
    }

    if (isCommandAllowed(command)) return;

    const health = configLoader.getHealth();
    const rules = [
      ...(health.mode === "fail-closed" ? [createFailClosedRule(health)] : []),
      createPermissionGateRule({
        patterns: config.permissionGate.patterns,
        useBuiltinMatchers: config.permissionGate.useBuiltinMatchers,
      }),
    ];
    const safety = await checkAction(action, rules);
    if (safety.kind === "safe") return;

    emitRiskDetected(pi, {
      feature: "permissionGate",
      risk: safety,
      context: { toolName, input: event.input },
    });

    if (!config.permissionGate.requireConfirmation) {
      ctx.ui.notify(`Dangerous command detected: ${safety.reason}`, "warning");
      return;
    }

    if (!ctx.hasUI) {
      const reason = `Dangerous command blocked (no UI to confirm): ${safety.reason}`;
      emitActionBlocked(pi, {
        feature: "permissionGate",
        action: safety.action,
        reason,
        block: { source: "nonInteractive", metadata: safety.metadata },
        context: { toolName, input: event.input },
      });
      return { block: true, reason };
    }

    const promptOpened = createPromptOpenedPayload({
      feature: "permissionGate",
      action: safety.action,
      reason: safety.reason,
      prompt: {
        kind: "permission",
        metadata: safety.metadata,
      },
      context: { toolName, input: event.input },
    });
    pi.events.emit(GUARDRAILS_PROMPT_OPENED_EVENT, promptOpened);

    let result: PermissionGateConfirmResult;
    let scopedGrant: {
      scope: PersistentPermissionGateScope;
      pattern: PatternConfig;
    } | null = null;
    try {
      const customResult = await ctx.ui.custom<PermissionGateConfirmResult>(
        createPermissionGateConfirmComponent(command, safety.reason),
      );

      if (customResult === undefined) {
        const indentedCommand = command.replace(/^/gm, "    ");
        const selection = await ctx.ui.select(
          `Dangerous command: ${safety.reason}\n\n${indentedCommand}`,
          [
            "Allow once",
            "Allow for session",
            "Allow for project",
            "Allow globally",
            "Deny",
            "Decline and stop",
          ],
        );
        if (selection === "Allow once") result = "allow";
        else if (selection === "Allow for session") result = "allow-session";
        else if (selection === "Allow for project") result = "allow-project";
        else if (selection === "Allow globally") result = "allow-global";
        else if (selection === "Decline and stop") result = "stop";
        else result = "deny";
      } else {
        result = customResult;
      }

      if (result === "allow-project" || result === "allow-global") {
        const scope: PersistentPermissionGateScope =
          result === "allow-project" ? "local" : "global";
        const choice = await chooseScopedGrantPattern(
          ctx,
          command,
          safety.metadata.pattern,
        );

        if (choice === "cancel") {
          ctx.ui.notify("Command allowed once (not saved)", "info");
          result = "allow";
        } else {
          scopedGrant = {
            scope,
            pattern: createScopedGrantPattern(
              command,
              safety.metadata.pattern,
              choice,
              config.permissionGate.patterns,
            ),
          };
        }
      }
    } finally {
      pi.events.emit(
        GUARDRAILS_PROMPT_CLOSED_EVENT,
        createPromptClosedPayload(promptOpened),
      );
    }

    if (result === "allow") return;
    if (result === "allow-session") {
      await saveCommandSessionGrant(command);
      return;
    }

    if (result === "allow-project" || result === "allow-global") {
      if (!scopedGrant) return;
      try {
        await saveCommandPersistentGrant(
          scopedGrant.scope,
          scopedGrant.pattern,
        );
      } catch (error) {
        ctx.ui.notify(
          `Command allowed once; grant not saved: ${error instanceof Error ? error.message : String(error)}`,
          "error",
        );
        return;
      }
      ctx.ui.notify(
        `Allowed pattern saved to ${scopedGrant.scope === "local" ? "project" : "global"} config`,
        "info",
      );
      return;
    }

    if (result === "stop") {
      const reason = "User declined and stopped dangerous command";
      emitActionBlocked(pi, {
        feature: "permissionGate",
        action: safety.action,
        reason,
        block: { source: "user-stop", metadata: safety.metadata },
        context: { toolName, input: event.input },
      });
      ctx.abort();
      return { block: true, reason };
    }

    const reason = "User denied dangerous command";
    emitActionBlocked(pi, {
      feature: "permissionGate",
      action: safety.action,
      reason,
      block: { source: "user", metadata: safety.metadata },
      context: { toolName, input: event.input },
    });
    return { block: true, reason };
  });
}
