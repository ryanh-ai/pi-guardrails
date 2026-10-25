import { homedir } from "node:os";
import { vol } from "memfs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { configLoader } from "../../src/shared/config";
import {
  createPendingGrant,
  isGrantTooBroad,
  pendingAllowedPaths,
  persistGrant,
  resolveAllowedPaths,
} from "./grants";

describe("path access grants", () => {
  it("resolves allowed paths relative to cwd, preserving kind", () => {
    expect(
      resolveAllowedPaths(
        [
          { kind: "directory", path: "../shared" },
          { kind: "directory", path: "logs" },
        ],
        "/repo/app",
      ),
    ).toEqual([
      { kind: "directory", path: "/repo/shared" },
      { kind: "directory", path: "/repo/app/logs" },
    ]);
  });

  it("converts pending grants to absolute allowed paths", () => {
    expect(
      pendingAllowedPaths([
        {
          kind: "file",
          storageGrant: { kind: "file", path: "/tmp/file.txt" },
          absolutePath: "/tmp/file.txt",
          scope: "memory",
        },
        {
          kind: "directory",
          storageGrant: { kind: "directory", path: "/tmp/logs" },
          absolutePath: "/tmp/logs",
          scope: "local",
        },
      ]),
    ).toEqual([
      { kind: "file", path: "/tmp/file.txt" },
      { kind: "directory", path: "/tmp/logs" },
    ]);
  });

  it("rejects home grants as too broad", () => {
    expect(isGrantTooBroad(`${homedir()}/`)).toBe(true);
    expect(isGrantTooBroad(`${homedir()}/project`)).toBe(false);
  });

  it("rejects filesystem root grants as too broad", () => {
    expect(isGrantTooBroad("/")).toBe(true);
    expect(isGrantTooBroad("//")).toBe(true);
    expect(isGrantTooBroad("/etc")).toBe(false);
  });

  it("creates pending grants with a storage grant", () => {
    expect(createPendingGrant("/tmp/logs", true, "local")).toEqual({
      kind: "directory",
      absolutePath: "/tmp/logs",
      scope: "local",
      storageGrant: { kind: "directory", path: "/tmp/logs" },
    });
  });

  it("creates pending grants for the global scope", () => {
    expect(createPendingGrant("/tmp/logs", true, "global")).toEqual({
      kind: "directory",
      absolutePath: "/tmp/logs",
      scope: "global",
      storageGrant: { kind: "directory", path: "/tmp/logs" },
    });
  });
});

describe("persistGrant", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps the grant for the session when its file can't be written", async () => {
    vol.fromJSON({ "/tmp/.keep": "" });
    await configLoader.load();
    const save = vi.spyOn(configLoader, "save");
    save.mockRejectedValueOnce(new Error("Refusing to overwrite x"));

    const error = await persistGrant(
      createPendingGrant("/tmp/outside", true, "global"),
    );

    expect(error).toBe("Refusing to overwrite x");
    expect(save).toHaveBeenLastCalledWith(
      "memory",
      expect.objectContaining({
        pathAccess: expect.objectContaining({
          allowedPaths: [{ kind: "directory", path: "/tmp/outside" }],
        }),
      }),
    );
  });

  it("returns nothing when the grant saves normally", async () => {
    vol.fromJSON({ "/tmp/.keep": "" });
    await configLoader.load();
    vi.spyOn(configLoader, "save").mockResolvedValue(undefined);

    expect(
      await persistGrant(createPendingGrant("/tmp/outside", true, "memory")),
    ).toBeUndefined();
  });
});
