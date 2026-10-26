import { readFile } from "node:fs/promises";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import { probeConfigFile } from "./health";
import { createGuardrailsConfigLoader } from "./loader";

const AGENT = "/tmp/pi-agent-guarded";
const GLOBAL = `${AGENT}/extensions/guardrails.json`;

describe("GuardedConfigLoader", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("still finds the pi-utils-settings internals it relies on", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: JSON.stringify({ version: pkg.version }) });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    const internals = loader as unknown as Record<string, unknown>;
    for (const key of [
      "globalPath",
      "localPath",
      "globalConfig",
      "localConfig",
    ]) {
      expect(key in internals).toBe(true);
    }
    expect(typeof internals.merge).toBe("function");
    expect(internals.globalPath).toBe(GLOBAL);
  });

  it("serves the cleaned merge, never the raw one", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({
      [GLOBAL]: JSON.stringify({ version: pkg.version, enabled: 0 }),
    });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    expect(loader.getConfig().enabled).toBe(true);
    await loader.save("memory", {});
    expect(loader.getConfig().enabled).toBe(true);
  });

  it("surfaces a config that can't be serialized instead of reporting success", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: JSON.stringify({ version: pkg.version }) });
    const loader = createGuardrailsConfigLoader();
    await loader.load();
    const circular: Record<string, unknown> = { version: pkg.version };
    circular.self = circular;

    await expect(loader.save("global", circular)).rejects.toThrow(TypeError);
    expect(JSON.parse(await readFile(GLOBAL, "utf-8"))).toEqual({
      version: pkg.version,
    });
  });

  it("treats an empty settings file as absent and lets saves replace it", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: "  \n" });
    expect((await probeConfigFile(GLOBAL)).state).toBe("absent");

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    await loader.save("global", { enabled: true });
    expect(JSON.parse(await readFile(GLOBAL, "utf-8")).enabled).toBe(true);
  });
});
