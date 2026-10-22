import type { Scope } from "@aliou/pi-utils-settings";
import type { GuardrailsConfig, PatternConfig } from "../../src/shared/config";
import { addTrustedProjectGrant, configLoader } from "../../src/shared/config";
import { compileCommandPatterns } from "../../src/shared/matching";

export type PersistentPermissionGateScope = Extract<Scope, "local" | "global">;

export function isCommandAllowed(command: string): boolean {
  const config = configLoader.getConfig();
  return compileCommandPatterns(config.permissionGate.allowedPatterns).some(
    (pattern) => pattern.test(command),
  );
}

export async function saveCommandSessionGrant(command: string): Promise<void> {
  const resolved = configLoader.getConfig();
  await configLoader.save("memory", {
    permissionGate: {
      allowedPatterns: [
        ...resolved.permissionGate.allowedPatterns,
        { pattern: exactCommandPattern(command), regex: true },
      ],
    },
  });
}

export async function saveCommandPersistentGrant(
  scope: PersistentPermissionGateScope,
  pattern: PatternConfig,
): Promise<void> {
  if (scope === "local") {
    // Project grants go to a store outside the project: the project's own
    // guardrails.json is writable by the agent, so its allowedPatterns are
    // ignored. Mirror the grant into memory so it applies right away.
    await addTrustedProjectGrant({
      pattern: pattern.pattern,
      ...(pattern.regex === undefined ? {} : { regex: pattern.regex }),
    });
    const memory = configLoader.getRawConfig("memory") ?? {};
    await configLoader.save("memory", {
      ...memory,
      permissionGate: {
        ...memory.permissionGate,
        allowedPatterns: [
          ...(memory.permissionGate?.allowedPatterns ?? []),
          pattern,
        ],
      },
    });
    return;
  }

  const existing = configLoader.getRawConfig(scope) ?? {};
  const existingAllowed = existing.permissionGate?.allowedPatterns ?? [];

  await configLoader.save(scope, {
    ...existing,
    permissionGate: {
      ...existing.permissionGate,
      allowedPatterns: [...existingAllowed, pattern],
    },
  } satisfies GuardrailsConfig);
}

/** Regex that matches exactly `command`, nothing more. */
export function exactCommandPattern(command: string): string {
  const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `^(?:${escaped})(?![\\s\\S])`;
}
