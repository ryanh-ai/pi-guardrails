import { dirname } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { checkAction } from "../../src/core";
import {
  type AllowedPath,
  normalizeForDisplay,
  type PathAccessState,
} from "../../src/core/paths";
import { configLoader, syncProjectTrust } from "../../src/shared/config";
import {
  createFeatureRegisterPayload,
  createPromptClosedPayload,
  createPromptOpenedPayload,
  emitActionBlocked,
  GUARDRAILS_FEATURE_REGISTER_EVENT,
  GUARDRAILS_FEATURE_REQUEST_EVENT,
  GUARDRAILS_PROMPT_CLOSED_EVENT,
  GUARDRAILS_PROMPT_OPENED_EVENT,
  setupLegacyPromptEventAlias,
} from "../../src/shared/events";
import { shellCommandForTool } from "../../src/shared/shell-tools";
import { piDocumentationPaths } from "./dynamic-resources";
import {
  createPendingGrant,
  isGrantTooBroad,
  type PendingPathGrant,
  pendingAllowedPaths,
  persistGrant,
  resolveAllowedPaths,
} from "./grants";
import {
  createPathAccessPromptComponent,
  type PromptResult,
  promptOptions,
} from "./prompt";
import { createPathAccessRule } from "./rules";
import { isReadOnlyTool, targetsForTool } from "./targets";

function notifyGrantFallback(
  ctx: {
    ui: { notify(message: string, type?: "info" | "warning" | "error"): void };
  },
  error: string | undefined,
): void {
  if (!error) return;
  ctx.ui.notify(`Access allowed for this session only: ${error}`, "warning");
}

function untrustedAlwaysScope(
  resolvedScope: string,
  ctx: {
    ui: { notify(message: string, type?: "info" | "warning" | "error"): void };
  },
): "memory" | "local" | "global" {
  if (resolvedScope === "local" && !configLoader.isProjectTrusted()) {
    ctx.ui.notify(
      "Access allowed for this session only: " +
        "project is not trusted, so the grant cannot be saved to the project config.",
      "warning",
    );
    return "memory";
  }
  return resolvedScope as "memory" | "local" | "global";
}

export default async function pathAccess(pi: ExtensionAPI) {
  await configLoader.load();

  // Pi docs paths depend only on `PI_PACKAGE_DIR` / the package root and are
  // fixed for the process lifetime, so resolve once at setup.
  const piDocsPaths = piDocumentationPaths();

  let currentSkillAllowedPaths: AllowedPath[] = [];

  pi.on("before_agent_start", (event) => {
    const skills = event.systemPromptOptions.skills;

    if (!skills || skills.length === 0) return;

    currentSkillAllowedPaths = skills.flatMap((skill) => [
      { kind: "file", path: skill.filePath },
      { kind: "directory", path: skill.baseDir },
    ]);
  });

  pi.events.on(GUARDRAILS_FEATURE_REQUEST_EVENT, () => {
    pi.events.emit(
      GUARDRAILS_FEATURE_REGISTER_EVENT,
      createFeatureRegisterPayload("pathAccess"),
    );
  });
  setupLegacyPromptEventAlias(pi, "pathAccess");

  pi.on("session_start", (_event, ctx) => syncProjectTrust(ctx));

  pi.on("tool_call", async (event, ctx) => {
    const config = configLoader.getConfig();
    if (
      !config.enabled ||
      !config.features.pathAccess ||
      config.pathAccess.mode === "allow"
    ) {
      return;
    }

    const input = event.input as Record<string, unknown>;
    if (
      config.pathAccess.applyTo === "write" &&
      isReadOnlyTool(event.toolName)
    ) {
      return;
    }
    const bashCommand = shellCommandForTool(
      event.toolName,
      input,
      ctx.cwd,
    )?.command;
    const targets = [
      ...new Set(await targetsForTool(event.toolName, input, ctx.cwd)),
    ];
    const acceptedGrants: PendingPathGrant[] = [];

    for (const absolutePath of targets) {
      const action = {
        kind: "file" as const,
        path: absolutePath,
        origin: event.toolName,
      };
      const state: PathAccessState = {
        cwd: ctx.cwd,
        mode: config.pathAccess.mode,
        allowedPaths: [
          ...resolveAllowedPaths(config.pathAccess.allowedPaths, ctx.cwd),
          ...piDocsPaths,
          ...currentSkillAllowedPaths,
          ...pendingAllowedPaths(acceptedGrants),
        ],
        hasUI: ctx.hasUI,
      };
      const safety = await checkAction(action, [createPathAccessRule(state)]);
      if (safety.kind === "safe") continue;

      if (config.pathAccess.mode === "block" || !ctx.hasUI) {
        emitActionBlocked(pi, {
          feature: "pathAccess",
          action: safety.action,
          reason: safety.reason,
          block: {
            source: ctx.hasUI ? "policy" : "nonInteractive",
            metadata: safety.metadata,
          },
          context: { toolName: event.toolName, input },
        });
        return { block: true, reason: safety.reason };
      }

      const parentDir = dirname(absolutePath);
      const showFileOptions =
        event.toolName !== "ls" && event.toolName !== "find";
      const dirPath = showFileOptions ? parentDir : absolutePath;
      const dirGrantable = !isGrantTooBroad(dirPath);
      const promptOpened = createPromptOpenedPayload({
        feature: "pathAccess",
        action: safety.action,
        reason: safety.reason,
        prompt: {
          kind: "confirmation",
          metadata: safety.metadata,
        },
        context: { toolName: event.toolName, input },
      });
      pi.events.emit(GUARDRAILS_PROMPT_OPENED_EVENT, promptOpened);

      let result: PromptResult;
      try {
        const customResult = await ctx.ui.custom<PromptResult>(
          createPathAccessPromptComponent(
            event.toolName,
            safety.metadata.displayPath,
            normalizeForDisplay(parentDir, ctx.cwd),
            ctx.cwd,
            showFileOptions,
            { command: bashCommand, dirGrantable },
          ),
        );

        if (customResult === undefined) {
          // RPC mode has no custom component support; fall back to a plain
          // select with the same options as the TUI prompt.
          const options = promptOptions(showFileOptions, dirGrantable);
          const dirNote = showFileOptions
            ? "\nDirectory grants apply to the parent directory."
            : "";
          const selection = await ctx.ui.select(
            `Allow access to ${safety.metadata.displayPath}? (outside ${ctx.cwd})${dirNote}`,
            options.map((option) => option.label),
          );
          result =
            options.find((option) => option.label === selection)?.result ??
            "deny";
        } else {
          result = customResult;
        }
      } finally {
        pi.events.emit(
          GUARDRAILS_PROMPT_CLOSED_EVENT,
          createPromptClosedPayload(promptOpened),
        );
      }

      if (result === "allow-file-once" || result === "allow-dir-once") {
        continue;
      }

      if (result === "allow-file-session" || result === "allow-file-always") {
        const scope =
          result === "allow-file-session"
            ? "memory"
            : untrustedAlwaysScope(config.pathAccess.alwaysScope, ctx);
        const grant = createPendingGrant(absolutePath, false, scope);
        acceptedGrants.push(grant);
        notifyGrantFallback(ctx, await persistGrant(grant));
        continue;
      }

      if (result === "allow-dir-session" || result === "allow-dir-always") {
        // Safety net: the prompt omits non-grantable directory options, but
        // keep the guard in case a result arrives through another path.
        if (isGrantTooBroad(dirPath)) {
          ctx.ui.notify(
            `Cannot grant access to ${normalizeForDisplay(dirPath, ctx.cwd)}/ — too broad. Treating as allow once.`,
            "warning",
          );
          continue;
        }
        const dirScope =
          result === "allow-dir-session"
            ? "memory"
            : untrustedAlwaysScope(config.pathAccess.alwaysScope, ctx);
        const grant = createPendingGrant(dirPath, true, dirScope);
        acceptedGrants.push(grant);
        notifyGrantFallback(ctx, await persistGrant(grant));
        continue;
      }

      const reason = "User denied access outside working directory";
      emitActionBlocked(pi, {
        feature: "pathAccess",
        action: safety.action,
        reason,
        block: { source: "user", metadata: safety.metadata },
        context: { toolName: event.toolName, input },
      });
      return { block: true, reason };
    }
  });
}
