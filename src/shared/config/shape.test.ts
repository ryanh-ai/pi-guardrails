import { join } from "node:path";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import { createGuardrailsConfigLoader } from "./loader";
import { normalizeConfigShape } from "./shape";

describe("normalizeConfigShape", () => {
  it("strips __proto__, constructor, and prototype keys and reports them", () => {
    // JSON.parse creates objects with literal string key "__proto__".
    const pollutionConfig = JSON.parse(
      '{"__proto__":{"enabled":false},"features":{"__proto__":{"policies":false}}}',
    );
    const { config, issues } = normalizeConfigShape(pollutionConfig);
    expect(Object.hasOwn(config, "__proto__")).toBe(false);
    expect(issues).toContain("__proto__ (prototype pollution key stripped)");
    expect(issues).toContain(
      "features.__proto__ (prototype pollution key stripped)",
    );
    // Stripping must not have polluted Object.prototype.
    expect(({} as Record<string, unknown>).enabled).toBeUndefined();
    expect(({} as Record<string, unknown>).policies).toBeUndefined();
  });

  it("strips __proto__ inside arrays", () => {
    const cfg = JSON.parse(
      '{"permissionGate":{"patterns":[{"__proto__":{"bad":true},"pattern":"x"}]}}',
    );
    const { config, issues } = normalizeConfigShape(cfg);
    const pat = config.permissionGate?.patterns?.[0] as unknown as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(pat, "__proto__")).toBe(false);
    expect(issues).toContain(
      "permissionGate.patterns[0].__proto__ (prototype pollution key stripped)",
    );
  });

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

  it("cleans optional pattern fields — deny list coerces, allow list drops", () => {
    const { config, issues } = normalizeConfigShape({
      permissionGate: {
        autoDenyPatterns: [
          { pattern: "a", regex: "true", description: 3, terminate: 1 },
        ],
        allowedPatterns: [{ pattern: "b", regex: "true" }],
      },
    });
    // Deny list: truthy non-boolean regex/terminate coerced to true.
    expect(config.permissionGate?.autoDenyPatterns).toEqual([
      { pattern: "a", regex: true, terminate: true },
    ]);
    expect(issues).toContain(
      "permissionGate.autoDenyPatterns[0].regex (coerced to true)",
    );
    expect(issues).toContain(
      "permissionGate.autoDenyPatterns[0].terminate (coerced to true)",
    );
    // Allow list: non-boolean regex dropped.
    expect(config.permissionGate?.allowedPatterns).toEqual([{ pattern: "b" }]);
    expect(issues).toContain("permissionGate.allowedPatterns[0].regex");
  });

  it("coerces truthy non-boolean regex/terminate on policy rule patterns", () => {
    const { config } = normalizeConfigShape({
      policies: {
        rules: [
          {
            id: "r",
            protection: "noAccess",
            patterns: [{ pattern: "secret", regex: 1, terminate: "yes" }],
            allowedPatterns: [{ pattern: "safe", regex: "true" }],
          },
        ],
      },
    });
    const rule = config.policies?.rules?.[0];
    expect(rule?.patterns).toEqual([
      { pattern: "secret", regex: true, terminate: true },
    ]);
    // Allow list still drops non-boolean regex.
    expect(rule?.allowedPatterns).toEqual([{ pattern: "safe" }]);
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

  it("prevents __proto__ in a project config from polluting Object.prototype", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    // Project config with __proto__ that tries to disable all rules.
    const pollutionJson = JSON.stringify(
      JSON.parse('{"__proto__":{"enabled":false}}'),
    );
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version }),
      [join(cwd, ".pi/extensions/guardrails.json")]: pollutionJson,
    });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    loader.setProjectTrusted(true, cwd);

    // Object.prototype must not have been modified.
    expect(({} as Record<string, unknown>).enabled).toBeUndefined();
    // Built-in policy rules must still be present.
    const config = loader.getConfig();
    expect(config.enabled).toBe(true);
    const ruleIds = config.policies.rules.map((r) => r.id);
    expect(ruleIds).toContain("home-ssh");
    // secret-files has no explicit `enabled`; with Object.prototype pollution
    // its `enabled` would have been false (inherited), causing it to be
    // filtered out. Verify it evaluates as enabled.
    const secretFiles = config.policies.rules.find(
      (r) => r.id === "secret-files",
    );
    expect(secretFiles).toBeDefined();
    expect(secretFiles?.enabled ?? true).toBe(true);
  });

  it("leaves built-in Object.prototype members intact", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    const cwd = process.cwd();
    const originalToString = Object.prototype.toString;
    const originalHasOwn = Object.prototype.hasOwnProperty;
    vol.fromJSON({
      [GLOBAL]: '{"__proto__":{"toString":1,"hasOwnProperty":2,"injected":3}}',
      [join(cwd, ".pi/extensions/guardrails.json")]:
        '{"__proto__":{"valueOf":4}}',
    });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    await loader.save("memory", {});

    expect(Object.prototype.toString).toBe(originalToString);
    expect(Object.prototype.hasOwnProperty).toBe(originalHasOwn);
    expect(typeof Object.prototype.valueOf).toBe("function");
    expect(Object.hasOwn(Object.prototype, "injected")).toBe(false);
    expect(String({})).toBe("[object Object]");
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
