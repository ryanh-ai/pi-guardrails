import { readFile } from "node:fs/promises";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../../../package.json" with { type: "json" };
import { probeConfigFile } from "./health";
import { createGuardrailsConfigLoader } from "./loader";

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

  it("reports a file under a dangling directory link as broken", async () => {
    vol.fromJSON({ "/agent/.keep": "" });
    vol.symlinkSync("/Volumes/Missing/extensions", "/agent/extensions");

    expect(
      await probeConfigFile("/agent/extensions/guardrails.json"),
    ).toMatchObject({
      state: "broken",
      reason: expect.stringContaining("/agent/extensions"),
    });
  });
});

describe("loader file health", () => {
  const AGENT = "/tmp/pi-agent-health";
  const GLOBAL = `${AGENT}/extensions/guardrails.json`;

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("reports a broken global file and refuses to save over it", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: "{ not json" });

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    expect(loader.getFileStates().global).toMatchObject({
      state: "broken",
      reason: expect.stringContaining("invalid JSON"),
    });
    await expect(
      loader.save("global", {
        permissionGate: { allowedPatterns: [{ pattern: "x" }] },
      }),
    ).rejects.toThrow(/Refusing to overwrite/);
    expect(await readFile(GLOBAL, "utf-8")).toBe("{ not json");
  });

  it("re-checks health at save time", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [GLOBAL]: JSON.stringify({ version: pkg.version }) });

    const loader = createGuardrailsConfigLoader();
    await loader.load();
    expect(loader.getFileStates().global?.state).toBe("ok");

    // The file breaks after load (e.g. its volume is unmounted).
    vol.unlinkSync(GLOBAL);
    vol.symlinkSync("/Volumes/Personal/guardrails.json", GLOBAL);

    await expect(loader.save("global", { enabled: true })).rejects.toThrow(
      /Refusing to overwrite/,
    );
  });

  it("treats a missing global file as normal", async () => {
    vi.stubEnv("PI_CODING_AGENT_DIR", AGENT);
    vol.fromJSON({ [`${AGENT}/.keep`]: "" });

    const loader = createGuardrailsConfigLoader();
    await loader.load();

    expect(loader.getFileStates().global?.state).toBe("absent");
    await loader.save("global", { enabled: true });
    expect(JSON.parse(await readFile(GLOBAL, "utf-8")).enabled).toBe(true);
  });
});
