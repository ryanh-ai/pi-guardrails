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

describe("trust root mismatch", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vol.reset();
  });

  it("sanitizes a project config when pi says trusted but the root is an ancestor dir", async () => {
    // Local config lives in process.cwd()/.pi/extensions/guardrails.json
    // (configRoot = process.cwd()), but we pretend the session started in
    // a subdirectory (cwd = process.cwd()+'/subdir') — roots don’t match.
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version }),
      [join(cwd, ".pi/extensions/guardrails.json")]: JSON.stringify(loosening),
    });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    // Pi says trusted, but cwd is a subdirectory → roots don’t match.
    loader.setProjectTrusted(true, join(cwd, "subdir"));
    // Config must be sanitized (loosening ignored).
    expect(loader.getConfig().enabled).toBe(true);
    expect(
      loader.getConfig().permissionGate.allowedPatterns.map((p) => p.pattern),
    ).not.toContain("project-allow");
    expect(loader.isProjectTrusted()).toBe(false);
  });

  it("trusts a project config when pi says trusted and the root matches cwd", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version }),
      [join(cwd, ".pi/extensions/guardrails.json")]: JSON.stringify(loosening),
    });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    // Pi says trusted and cwd matches the config root → trusted.
    loader.setProjectTrusted(true, cwd);
    expect(loader.getConfig().enabled).toBe(false);
    expect(
      loader.getConfig().permissionGate.allowedPatterns.map((p) => p.pattern),
    ).toContain("project-allow");
    expect(loader.isProjectTrusted()).toBe(true);
  });

  it("old pi without cwd treats the project as trusted (backward compat)", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version }),
      [join(cwd, ".pi/extensions/guardrails.json")]: JSON.stringify(loosening),
    });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    // Old pi: no isProjectTrusted, no cwd → trusted (backward compat).
    loader.setProjectTrusted(undefined, undefined);
    expect(loader.isProjectTrusted()).toBe(true);
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

  it("drops alwaysScope from untrusted project config", () => {
    const { config, ignored } = sanitizeUntrustedLocal(
      { pathAccess: { alwaysScope: "global" } },
      new Set(),
      { mode: "ask", applyTo: "all" },
    );
    expect(config.pathAccess?.alwaysScope).toBeUndefined();
    expect(ignored).toContain("pathAccess.alwaysScope");
  });
});

describe("syncProjectTrust", () => {
  it("passes pi's answer and cwd to setProjectTrusted", () => {
    const spy = vi.spyOn(configLoader, "setProjectTrusted");
    syncProjectTrust({ isProjectTrusted: () => false, cwd: "/repo" });
    expect(spy).toHaveBeenLastCalledWith(false, "/repo");
    // Old pi (no isProjectTrusted): passes undefined as piTrusted.
    syncProjectTrust({ cwd: "/repo" });
    expect(spy).toHaveBeenLastCalledWith(undefined, "/repo");
    // No cwd available: passes undefined.
    syncProjectTrust({});
    expect(spy).toHaveBeenLastCalledWith(undefined, undefined);
    spy.mockRestore();
  });
});
