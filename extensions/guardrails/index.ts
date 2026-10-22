import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { checkAction } from "../../src/core";
import { configLoader } from "../../src/shared/config";
import {
  createFeatureRequestPayload,
  emitActionBlocked,
  GUARDRAILS_FEATURE_REGISTER_EVENT,
  GUARDRAILS_FEATURE_REQUEST_EVENT,
  type GuardrailsFeatureId,
  type GuardrailsFeatureRegisterPayload,
} from "../../src/shared/events";
import { trackSessionInput } from "../../src/shared/shell-tools";
import { registerGuardrailsExamplesCommand } from "./commands/examples";
import { registerGuardrailsOnboardingCommand } from "./commands/onboarding";
import { isOnboardingPending } from "./commands/onboarding/config";
import { registerGuardrailsSettings } from "./commands/settings";
import {
  BLOCKED_TOOLS,
  compilePolicies,
  createPolicyRules,
  protectionRank,
} from "./rules";
import { extractTargets } from "./targets";

/** Surface unreadable or sanitized config on every session start. */
function notifyConfigHealth(ctx: {
  ui: { notify(message: string, type?: "info" | "warning" | "error"): void };
}): void {
  const health = configLoader.getHealth();
  const { global, local } = health;
  if (global.state === "broken") {
    const effect =
      health.mode === "snapshot"
        ? `Using the last good snapshot from ${health.snapshotSavedAt ?? "an earlier load"}.`
        : "No snapshot is available: every shell command needs confirmation.";
    ctx.ui.notify(
      [
        `Guardrails: global config is unreadable (${global.reason}).`,
        `  ${global.path}`,
        effect,
        "Saving grants to the global config is disabled until the file is fixed and pi is reloaded.",
      ].join("\n"),
      "error",
    );
  }
  if (local.state === "broken") {
    ctx.ui.notify(
      `Guardrails: project config is unreadable and was skipped (${local.reason}).\n  ${local.path}`,
      "warning",
    );
  }
  if (health.globalIssues.length > 0) {
    ctx.ui.notify(
      [
        "Guardrails: ignored invalid values in the global config:",
        ...health.globalIssues.map((issue) => `- ${issue}`),
        `  ${global.path}`,
      ].join("\n"),
      "warning",
    );
  }
  if (health.localIssues.length > 0) {
    ctx.ui.notify(
      [
        "Guardrails: ignored invalid values in the project config:",
        ...health.localIssues.map((issue) => `- ${issue}`),
        `  ${local.path}`,
      ].join("\n"),
      "warning",
    );
  }
  if (health.ignoredLocalKeys.length > 0) {
    ctx.ui.notify(
      [
        "Guardrails: ignored project config settings that would weaken protection:",
        ...health.ignoredLocalKeys.map((key) => `- ${key}`),
        `  ${local.path}`,
      ].join("\n"),
      "warning",
    );
  }
}

function setupPolicyHook(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event, ctx) => {
    const config = configLoader.getConfig();
    if (!config.enabled || !config.features.policies) return;

    const policies = compilePolicies(config.policies.rules)
      .filter((policy) => BLOCKED_TOOLS[policy.protection].has(event.toolName))
      .sort(
        (a, b) => protectionRank(b.protection) - protectionRank(a.protection),
      );
    if (policies.length === 0) return;

    const input = event.input as Record<string, unknown>;
    const targets = await extractTargets(
      { toolName: event.toolName, input, toolCallId: event.toolCallId },
      ctx.cwd,
      policies,
    );
    const rules = createPolicyRules(policies, ctx.cwd);

    for (const target of targets) {
      const safety = await checkAction(
        {
          kind: "file",
          path: target.path,
          unresolved: target.unresolved,
          origin: event.toolName,
        },
        rules,
      );
      if (safety.kind === "safe") continue;

      emitActionBlocked(pi, {
        feature: "policies",
        action: safety.action,
        reason: safety.reason,
        block: { source: "policy", metadata: safety.metadata },
        context: { toolName: event.toolName, input },
      });
      return { block: true, reason: safety.reason };
    }
  });
}

export default async function guardrails(pi: ExtensionAPI) {
  await configLoader.load();

  const loadedFeatures = new Set<GuardrailsFeatureId>(["policies"]);

  pi.events.on(GUARDRAILS_FEATURE_REGISTER_EVENT, (data: unknown) => {
    const payload = data as GuardrailsFeatureRegisterPayload;
    loadedFeatures.add(payload.feature.id);
  });

  registerGuardrailsSettings(pi, {
    getLoadedFeatures: () => loadedFeatures,
  });

  registerGuardrailsExamplesCommand(pi);
  if (isOnboardingPending(configLoader.getRawConfig("global"))) {
    registerGuardrailsOnboardingCommand(pi);
  }
  setupPolicyHook(pi);
  trackSessionInput(pi);

  pi.on("session_start", (_event, ctx) => {
    loadedFeatures.clear();
    loadedFeatures.add("policies");

    pi.events.emit(
      GUARDRAILS_FEATURE_REQUEST_EVENT,
      createFeatureRequestPayload(),
    );

    const warnings = configLoader.drainMessages();
    notifyConfigHealth(ctx);
    if (warnings.length === 1) {
      ctx.ui.notify(warnings[0], "warning");
    } else if (warnings.length > 1) {
      ctx.ui.notify(
        [
          "Guardrails warnings:",
          ...warnings.map((warning) => `- ${warning}`),
        ].join("\n"),
        "warning",
      );
    }
  });
}
