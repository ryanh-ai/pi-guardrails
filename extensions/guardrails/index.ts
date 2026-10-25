import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { checkAction } from "../../src/core";
import { configLoader, syncProjectTrust } from "../../src/shared/config";
import {
  createFeatureRequestPayload,
  emitActionBlocked,
  GUARDRAILS_FEATURE_REGISTER_EVENT,
  GUARDRAILS_FEATURE_REQUEST_EVENT,
  type GuardrailsFeatureId,
  type GuardrailsFeatureRegisterPayload,
} from "../../src/shared/events";
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
      { toolName: event.toolName, input },
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

  pi.on("session_start", (_event, ctx) => {
    syncProjectTrust(ctx);
    loadedFeatures.clear();
    loadedFeatures.add("policies");

    pi.events.emit(
      GUARDRAILS_FEATURE_REQUEST_EVENT,
      createFeatureRequestPayload(),
    );

    const files = configLoader.getFileStates();
    if (files.global?.state === "broken") {
      ctx.ui.notify(
        [
          `Guardrails: the global config can't be read (${files.global.reason}).`,
          `  ${files.global.path}`,
          "Running on built-in defaults: your custom rules are NOT active. Saving to this file is refused until it is fixed and pi is reloaded.",
        ].join("\n"),
        "error",
      );
    }
    if (files.local?.state === "broken") {
      ctx.ui.notify(
        `Guardrails: the project config can't be read and was skipped (${files.local.reason}).\n  ${files.local.path}`,
        "warning",
      );
    }

    const ignored = configLoader.getIgnoredLocalKeys();
    if (ignored.length > 0) {
      ctx.ui.notify(
        [
          "Guardrails: this project is not trusted, so project settings that would loosen protection are ignored:",
          ...ignored.map((key) => `- ${key}`),
          "Trust the project in pi to apply them.",
        ].join("\n"),
        "warning",
      );
    }

    const shape = configLoader.getShapeIssues();
    for (const [scope, issues] of [
      ["global", shape.global],
      ["project", shape.local],
    ] as const) {
      if (issues.length === 0) continue;
      ctx.ui.notify(
        [
          `Guardrails: ignored or fixed invalid values in the ${scope} config:`,
          ...issues.map((issue) => `- ${issue}`),
        ].join("\n"),
        "warning",
      );
    }

    const warnings = configLoader.drainMessages();
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
