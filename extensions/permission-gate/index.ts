import {
  type ExtensionAPI,
  isToolCallEventType,
} from "@earendil-works/pi-coding-agent";
import { checkAction } from "../../src/core";
import type { PatternConfig } from "../../src/shared/config";
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
import {
  createPermissionGateRule,
  formatAutoDenyReason,
  matchCommandPattern,
} from "./rules";

type ScopedGrantChoice = "exact" | "class" | "cancel";

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
    if (!isToolCallEventType("bash", event)) return;

    const command = event.input.command;
    const action = { kind: "command" as const, command, origin: "bash" };
    if (isCommandAllowed(command)) return;

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
        context: { toolName: "bash", input: event.input },
      });

      return { block: true, reason };
    }

    const safety = await checkAction(action, [
      createPermissionGateRule({
        patterns: config.permissionGate.patterns,
        useBuiltinMatchers: config.permissionGate.useBuiltinMatchers,
      }),
    ]);
    if (safety.kind === "safe") return;

    emitRiskDetected(pi, {
      feature: "permissionGate",
      risk: safety,
      context: { toolName: "bash", input: event.input },
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
        context: { toolName: "bash", input: event.input },
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
      context: { toolName: "bash", input: event.input },
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
        const selection = await ctx.ui.select(
          `Dangerous command: ${safety.reason}`,
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
      await saveCommandPersistentGrant(scopedGrant.scope, scopedGrant.pattern);
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
        context: { toolName: "bash", input: event.input },
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
      context: { toolName: "bash", input: event.input },
    });
    return { block: true, reason };
  });
}
