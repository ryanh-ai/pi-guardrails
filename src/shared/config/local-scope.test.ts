import { join } from "node:path";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import {
  configLoader,
  createGuardrailsConfigLoader,
  syncProjectTrust,
} from "./loader";
import { sanitizeUntrustedLocal } from "./local-scope";

const AGENT = "/tmp/pi-agent-trust";
const GLOBAL = `${AGENT}/extensions/guardrails.json`;

const loosening = {
  version: pkg.version,
  enabled: false,
  features: { permissionGate: false, policies: true },
  permissionGate: {
    requireConfirmation: false,
    customPatterns: [],
    allowedPatterns: [{ pattern: "project-allow" }],
    autoDenyPatterns: [{ pattern: "project-deny" }],
  },
  policies: {
    rules: [
      { id: "secret-files", patterns: [{ pattern: "x" }], protection: "none" },
      {
        id: "project-extra",
        patterns: [{ pattern: "keys/**" }],
        protection: "noAccess",
      },
    ],
  },
  pathAccess: {
    mode: "allow",
    applyTo: "write",
    allowedPaths: [{ kind: "directory", path: "~" }],
  },
};

async function loadWithProject(project: object) {
  vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
  vol.fromJSON({
    [GLOBAL]: JSON.stringify({
      version: pkg.version,
      permissionGate: { allowedPatterns: [{ pattern: "global-allow" }] },
    }),
    [join(process.cwd(), ".pi/extensions/guardrails.json")]:
      JSON.stringify(project),
  });
  const loader = createGuardrailsConfigLoader();
  await loader.load();
  return loader;
}

describe("project config and pi project trust", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("ignores loosening project settings until the project is trusted", async () => {
    const loader = await loadWithProject(loosening);
    const config = loader.getConfig();

    expect(config.enabled).toBe(true);
    expect(config.features.permissionGate).toBe(true);
    expect(config.permissionGate.requireConfirmation).toBe(true);
    expect(config.permissionGate.patterns.length).toBeGreaterThan(0);
    expect(config.permissionGate.allowedPatterns.map((p) => p.pattern)).toEqual(
      ["global-allow"],
    );
    expect(config.pathAccess.mode).toBe("ask");
    expect(config.pathAccess.allowedPaths).not.toContainEqual({
      kind: "directory",
      path: "~",
    });
    // Tightening still applies.
    expect(
      config.permissionGate.autoDenyPatterns.map((p) => p.pattern),
    ).toEqual(["project-deny"]);
    const rules = Object.fromEntries(
      config.policies.rules.map((rule) => [rule.id, rule]),
    );
    expect(rules["secret-files"]?.protection).toBe("noAccess");
    expect(rules["project-extra"]).toBeDefined();
    expect(loader.getIgnoredLocalKeys()).toEqual([
      "enabled",
      "features.permissionGate",
      "permissionGate.requireConfirmation",
      "permissionGate.customPatterns",
      "permissionGate.allowedPatterns",
      "policies.rules[secret-files]",
      "pathAccess.mode",
      "pathAccess.applyTo",
      "pathAccess.allowedPaths",
    ]);
  });

  it("honors the whole project config once pi trusts the project", async () => {
    const loader = await loadWithProject(loosening);
    loader.setProjectTrusted(true);
    const config = loader.getConfig();

    expect(config.enabled).toBe(false);
    expect(config.permissionGate.allowedPatterns.map((p) => p.pattern)).toEqual(
      ["global-allow", "project-allow"],
    );
    expect(config.pathAccess.mode).toBe("allow");
    expect(loader.getIgnoredLocalKeys()).toEqual([]);

    loader.setProjectTrusted(false);
    expect(loader.getConfig().enabled).toBe(true);
  });

  it("keeps a project setting that is stricter than global", async () => {
    const loader = await loadWithProject({
      version: pkg.version,
      pathAccess: { mode: "block", applyTo: "all" },
    });

    expect(loader.getConfig().pathAccess.mode).toBe("block");
    expect(loader.getIgnoredLocalKeys()).toEqual([]);
  });

  it("keeps trust across saves", async () => {
    const loader = await loadWithProject(loosening);
    await loader.save("memory", {
      permissionGate: { allowedPatterns: [{ pattern: "session" }] },
    });

    expect(loader.getConfig().enabled).toBe(true);
    expect(loader.getIgnoredLocalKeys()).toContain("enabled");
  });
});

describe("sanitizeUntrustedLocal", () => {
  it("compares pathAccess against the global setting", () => {
    const strictGlobal = { mode: "block", applyTo: "all" };
    expect(
      sanitizeUntrustedLocal(
        { pathAccess: { mode: "ask" } },
        new Set(),
        strictGlobal,
      ).ignored,
    ).toEqual(["pathAccess.mode"]);
    expect(
      sanitizeUntrustedLocal({ pathAccess: { applyTo: "write" } }, new Set(), {
        mode: "ask",
        applyTo: "write",
      }).ignored,
    ).toEqual([]);
  });
});

describe("syncProjectTrust", () => {
  it("uses ctx.isProjectTrusted(), and treats older pi as trusted", () => {
    const spy = vi.spyOn(configLoader, "setProjectTrusted");
    syncProjectTrust({ isProjectTrusted: () => false });
    expect(spy).toHaveBeenLastCalledWith(false);
    syncProjectTrust({});
    expect(spy).toHaveBeenLastCalledWith(true);
    spy.mockRestore();
  });
});
