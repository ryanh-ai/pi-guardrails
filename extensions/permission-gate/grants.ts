import type { Scope } from "@aliou/pi-utils-settings";
import type { GuardrailsConfig, PatternConfig } from "../../src/shared/config";
import { configLoader } from "../../src/shared/config";
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
        { pattern: command },
      ],
    },
  });
}

export async function saveCommandPersistentGrant(
  scope: PersistentPermissionGateScope,
  pattern: PatternConfig,
): Promise<void> {
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
