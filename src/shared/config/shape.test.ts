import { join } from "node:path";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import { createGuardrailsConfigLoader } from "./loader";
import { normalizeConfigShape } from "./shape";

describe("normalizeConfigShape", () => {
  it("drops non-boolean flags whose default is stricter", () => {
    const { config, issues } = normalizeConfigShape({
      enabled: 0,
      applyBuiltinDefaults: null,
      features: { permissionGate: 0, policies: "" },
      permissionGate: { requireConfirmation: "no", useBuiltinMatchers: 0 },
    });
    expect(config).toEqual({
      features: {},
      permissionGate: {},
    });
    expect(issues).toEqual(
      expect.arrayContaining([
        "enabled",
        "applyBuiltinDefaults",
        "features.permissionGate",
        "features.policies",
        "permissionGate.requireConfirmation",
        "permissionGate.useBuiltinMatchers",
      ]),
    );
  });

  it("keeps a rule when only some of its entries are invalid", () => {
    const { config, issues } = normalizeConfigShape({
      policies: {
        rules: [
          {
            id: "keys",
            protection: "noAccess",
            patterns: [{ pattern: "~/.keys/**" }, "~/.typo/**", null],
            allowedPatterns: [{ pattern: "~/.keys/*.pub" }, 5],
          },
        ],
      },
    });
    expect(config.policies?.rules).toEqual([
      {
        id: "keys",
        protection: "noAccess",
        patterns: [{ pattern: "~/.keys/**" }],
        allowedPatterns: [{ pattern: "~/.keys/*.pub" }],
      },
    ]);
    expect(issues).toEqual(
      expect.arrayContaining([
        "policies.rules[keys].patterns[2 invalid entries]",
        "policies.rules[keys].allowedPatterns[1 invalid entries]",
      ]),
    );
  });

  it("fixes rule flags toward the stricter value", () => {
    const { config } = normalizeConfigShape({
      policies: {
        rules: [
          {
            id: "r",
            protection: "readonly",
            onlyIfExists: "false",
            respectCwd: "no",
            enabled: "yes",
            patterns: [{ pattern: "x" }],
          },
        ],
      },
    });
    expect(config.policies?.rules?.[0]).toEqual({
      id: "r",
      protection: "noAccess",
      onlyIfExists: false,
      respectCwd: false,
      patterns: [{ pattern: "x" }],
    });
  });

  it("drops rules without an id or usable patterns", () => {
    const { config, issues } = normalizeConfigShape({
      policies: {
        rules: [
          null,
          { protection: "noAccess", patterns: [{ pattern: "x" }] },
          { id: "empty", protection: "noAccess", patterns: ["x"] },
          { id: "nolist", protection: "noAccess", patterns: "x" },
        ],
      },
    });
    expect(config.policies?.rules).toEqual([]);
    expect(issues).toEqual(
      expect.arrayContaining([
        "policies.rules[0] (no id)",
        "policies.rules[empty] (no valid patterns)",
        "policies.rules[nolist].patterns (not a list)",
      ]),
    );
  });

  it("validates pathAccess fields", () => {
    const { config, issues } = normalizeConfigShape({
      pathAccess: {
        mode: "sometimes",
        applyTo: 3,
        alwaysScope: "forever",
        allowedPaths: [
          { kind: "directory", path: "/tmp/x" },
          { kind: "folder", path: "/y" },
          "/z",
        ],
      },
    });
    expect(config.pathAccess).toEqual({
      allowedPaths: [{ kind: "directory", path: "/tmp/x" }],
    });
    expect(issues).toEqual(
      expect.arrayContaining([
        "pathAccess.mode",
        "pathAccess.applyTo",
        "pathAccess.alwaysScope",
        "pathAccess.allowedPaths[2 invalid entries]",
      ]),
    );
    expect(
      normalizeConfigShape({ pathAccess: { allowedPaths: {} } }).config,
    ).toEqual({ pathAccess: {} });
  });

  it("cleans optional pattern fields", () => {
    const { config } = normalizeConfigShape({
      permissionGate: {
        autoDenyPatterns: [
          { pattern: "a", regex: "true", description: 3, terminate: 1 },
        ],
      },
    });
    expect(config.permissionGate?.autoDenyPatterns).toEqual([{ pattern: "a" }]);
  });

  it("leaves a valid config unchanged", () => {
    const valid = {
      version: "0.20.0",
      enabled: true,
      features: { pathAccess: true },
      permissionGate: {
        patterns: [{ pattern: "x", description: "y" }],
        autoDenyPatterns: [{ pattern: "z", regex: true, terminate: true }],
      },
      policies: {
        rules: [
          { id: "r", protection: "readOnly", patterns: [{ pattern: "p" }] },
        ],
      },
      pathAccess: {
        mode: "ask",
        applyTo: "write",
        alwaysScope: "global",
        allowedPaths: [{ kind: "file", path: "/dev/null" }],
      },
    };
    expect(normalizeConfigShape(valid)).toEqual({ config: valid, issues: [] });
  });
});

describe("loader shape checks", () => {
  const AGENT = "/tmp/pi-agent-shape";
  const GLOBAL = `${AGENT}/extensions/guardrails.json`;

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("keeps the rest of a global config when one value is malformed", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const raw = {
      version: pkg.version,
      enabled: 0,
      permissionGate: { autoDenyPatterns: [{ pattern: "custom-deny" }, null] },
      pathAccess: { allowedPaths: {} },
      policies: {
        rules: [
          null,
          {
            id: "mine",
            protection: "noAccess",
            patterns: [{ pattern: "~/.mine/**" }],
          },
        ],
      },
    };
    vol.fromJSON({ [GLOBAL]: JSON.stringify(raw) });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    const config = loader.getConfig();

    expect(config.enabled).toBe(true);
    expect(config.permissionGate.autoDenyPatterns).toEqual([
      { pattern: "custom-deny" },
    ]);
    expect(config.policies.rules.map((rule) => rule.id)).toContain("mine");
    expect(loader.getShapeIssues().global).toEqual(
      expect.arrayContaining(["enabled", "pathAccess.allowedPaths"]),
    );
    expect(loader.getShapeIssues().local).toEqual([]);
    // The raw file config is left alone for saves.
    expect(loader.getRawConfig("global")).toMatchObject({ enabled: 0 });
  });

  it("re-applies shape checks after a save", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version, enabled: 0 }),
      [join(cwd, ".pi/.keep")]: "",
    });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    await loader.save("memory", {
      permissionGate: { allowedPatterns: [{ pattern: "session" }] },
    });

    expect(loader.getConfig().enabled).toBe(true);
    expect(
      loader.getConfig().permissionGate.allowedPatterns.map((p) => p.pattern),
    ).toContain("session");
  });
});
