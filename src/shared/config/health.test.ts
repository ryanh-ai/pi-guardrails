import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import { addTrustedProjectGrant, probeConfigFile } from "./health";
import { createGuardrailsConfigLoader } from "./loader";

const AGENT = "/tmp/pi-agent-health";
const GLOBAL = `${AGENT}/extensions/guardrails.json`;
const SNAPSHOT = `${AGENT}/state/guardrails/last-good-global.json`;

const customGlobal = {
  version: pkg.version,
  permissionGate: {
    autoDenyPatterns: [{ pattern: "custom-deny" }],
    allowedPatterns: [{ pattern: "custom-allow" }],
  },
};

function denyPatterns(loader: ReturnType<typeof createGuardrailsConfigLoader>) {
  return loader
    .getConfig()
    .permissionGate.autoDenyPatterns.map((pattern) => pattern.pattern);
}

describe("probeConfigFile", () => {
  it("classifies absent, ok, dangling, and invalid files", async () => {
    vol.fromJSON({
      "/cfg/ok.json": "{}",
      "/cfg/bad.json": "{ nope",
      "/cfg/array.json": "[]",
    });
    vol.symlinkSync("/Volumes/Missing/guardrails.json", "/cfg/link.json");

    expect(await probeConfigFile("/cfg/none.json")).toMatchObject({
      state: "absent",
    });
    expect(await probeConfigFile("/cfg/ok.json")).toMatchObject({
      state: "ok",
    });
    expect(await probeConfigFile("/cfg/link.json")).toMatchObject({
      state: "broken",
      reason: expect.stringContaining("dangling symlink"),
    });
    expect(await probeConfigFile("/cfg/bad.json")).toMatchObject({
      state: "broken",
      reason: expect.stringContaining("invalid JSON"),
    });
    expect(await probeConfigFile("/cfg/array.json")).toMatchObject({
      state: "broken",
      reason: "not a JSON object",
    });
  });
});

describe("guardrails config health", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("runs on defaults quietly when the global file is absent", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [`${AGENT}/.keep`]: "" });

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    expect(loader.getHealth()).toMatchObject({
      mode: "normal",
      global: { state: "absent" },
    });
  });

  it("snapshots a good global config and uses it when the file breaks", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: JSON.stringify(customGlobal) });

    const good = createGuardrailsConfigLoader();
    await good.load();
    expect(good.getHealth().mode).toBe("normal");
    const snapshot = JSON.parse(await readFile(SNAPSHOT, "utf-8"));
    expect(snapshot.config.permissionGate.autoDenyPatterns).toEqual([
      { pattern: "custom-deny" },
    ]);

    // The volume holding the real file goes away.
    vol.unlinkSync(GLOBAL);
    vol.symlinkSync("/Volumes/Personal/pidot/guardrails.json", GLOBAL);

    const broken = createGuardrailsConfigLoader();
    await broken.load();
    expect(broken.getHealth()).toMatchObject({
      mode: "snapshot",
      global: { state: "broken" },
    });
    expect(broken.getHealth().snapshotSavedAt).toBe(snapshot.savedAt);
    expect(denyPatterns(broken)).toContain("custom-deny");
  });

  it("fails closed when the global file is broken and no snapshot exists", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: "{ not json" });

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    expect(loader.getHealth()).toMatchObject({
      mode: "fail-closed",
      global: {
        state: "broken",
        reason: expect.stringContaining("invalid JSON"),
      },
    });
  });

  it("refuses to save over a broken global file", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: "{ not json" });

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    await expect(
      loader.save("global", {
        permissionGate: { allowedPatterns: [{ pattern: "x" }] },
      }),
    ).rejects.toThrow(/Refusing to overwrite/);
    expect(await readFile(GLOBAL, "utf-8")).toBe("{ not json");
  });

  it("ignores project settings that would weaken protection", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({
        ...customGlobal,
        policies: {
          rules: [
            {
              id: "home-aws",
              patterns: [{ pattern: "~/.aws/**" }],
              protection: "noAccess",
            },
          ],
        },
      }),
      [join(cwd, ".pi/extensions/guardrails.json")]: JSON.stringify({
        version: pkg.version,
        enabled: false,
        features: { permissionGate: false, policies: true },
        permissionGate: {
          requireConfirmation: false,
          useBuiltinMatchers: false,
          customPatterns: [],
          allowedPatterns: [{ pattern: ".*", regex: true }],
          autoDenyPatterns: [{ pattern: "project-deny" }],
        },
        policies: {
          rules: [
            { id: "home-aws", patterns: [], protection: "none" },
            { id: "secret-files", patterns: [], protection: "none" },
            {
              id: "project-extra",
              patterns: [{ pattern: "keys/**" }],
              protection: "noAccess",
            },
          ],
        },
      }),
    });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    const config = loader.getConfig();

    expect(config.enabled).toBe(true);
    expect(config.features.permissionGate).toBe(true);
    expect(config.permissionGate.requireConfirmation).toBe(true);
    expect(config.permissionGate.useBuiltinMatchers).toBe(true);
    expect(config.permissionGate.patterns.length).toBeGreaterThan(0);
    expect(
      config.permissionGate.allowedPatterns.map((pattern) => pattern.pattern),
    ).toEqual(["custom-allow"]);
    // Additions still apply.
    expect(denyPatterns(loader)).toEqual(["custom-deny", "project-deny"]);
    const rules = Object.fromEntries(
      config.policies.rules.map((rule) => [rule.id, rule]),
    );
    expect(rules["home-aws"].protection).toBe("noAccess");
    expect(rules["secret-files"].protection).toBe("noAccess");
    expect(rules["project-extra"]).toBeDefined();
    expect(loader.getHealth().ignoredLocalKeys).toEqual([
      "enabled",
      "features.permissionGate",
      "permissionGate.useBuiltinMatchers",
      "permissionGate.requireConfirmation",
      "permissionGate.customPatterns",
      "permissionGate.allowedPatterns",
      "policies.rules[home-aws]",
      "policies.rules[secret-files]",
    ]);
  });

  it("applies trusted project grants for the current project only", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify(customGlobal),
      [join(cwd, ".pi/.keep")]: "",
    });
    await addTrustedProjectGrant({ pattern: "project-grant" });
    await addTrustedProjectGrant({ pattern: "elsewhere" }, "/some/other/repo");

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    expect(
      loader
        .getConfig()
        .permissionGate.allowedPatterns.map((pattern) => pattern.pattern),
    ).toEqual(["custom-allow", "project-grant"]);
  });
});
