import { describe, expect, it } from "vitest";
import { checkDangerousCommand, matchDangerousCommand } from "./dangerous";
import { commandLevels } from "./wrappers";

function check(command: string): string | undefined {
  return checkDangerousCommand({
    command,
    patterns: [],
    useBuiltinMatchers: true,
    fallbackPatterns: [],
  })?.description;
}

describe("commandLevels", () => {
  it("keeps the words as written first", () => {
    expect(commandLevels(["sudo", "rm", "-rf", "x"])[0]).toEqual([
      "sudo",
      "rm",
      "-rf",
      "x",
    ]);
  });

  it("unwraps wrappers and reduces paths to basenames", () => {
    expect(
      commandLevels(["env", "-i", "A=1", "B=2", "/usr/bin/git", "push"]),
    ).toEqual([
      ["env", "-i", "A=1", "B=2", "/usr/bin/git", "push"],
      ["/usr/bin/git", "push"],
      ["git", "push"],
    ]);
    expect(
      commandLevels(["nice", "-n", "5", "nohup", "rm", "-rf", "x"]).at(-1),
    ).toEqual(["rm", "-rf", "x"]);
    expect(
      commandLevels(["timeout", "-s", "KILL", "30", "git", "status"]).at(-1),
    ).toEqual(["git", "status"]);
    expect(
      commandLevels(["xargs", "-I", "{}", "-n", "1", "git", "branch", "-D"]).at(
        -1,
      ),
    ).toEqual(["git", "branch", "-D"]);
  });

  it("does not unwrap `command -v`, which only looks a name up", () => {
    expect(commandLevels(["command", "-v", "rm"])).toEqual([
      ["command", "-v", "rm"],
    ]);
  });

  it("keeps the wrapped command's own -v", () => {
    expect(commandLevels(["command", "git", "-v"]).at(-1)).toEqual([
      "git",
      "-v",
    ]);
  });
});

describe("built-in matchers through wrappers", () => {
  const cases: [string, RegExp][] = [
    ["env GIT_TRACE=1 git push --force", /force push/],
    ["/usr/bin/git reset --hard", /reset --hard/],
    ["command git push -f", /force push/],
    ["nice -n 10 git clean -fd", /clean -f/],
    ["exec git stash clear", /stash clear/],
    ["xargs git branch -D", /force-delete/],
    ["timeout 60 git push --mirror", /mirror/],
    ["stdbuf -oL git push -f", /force push/],
    ["/bin/rm -rf build", /recursive force delete/],
    ["env rm -rf build", /recursive force delete/],
    ["env -S 'git push --force'", /force push/],
    ["sudo git push -f", /superuser command/],
  ];
  for (const [command, description] of cases) {
    it(command, () => {
      expect(check(command)).toMatch(description);
    });
  }

  it("leaves harmless wrapped commands alone", () => {
    for (const command of [
      "env FOO=1 git status",
      "command -v rm",
      "nice git log",
      "/usr/bin/git push",
      "xargs -n1 echo",
    ]) {
      expect(check(command)).toBeUndefined();
    }
  });
});

describe("matchDangerousCommand", () => {
  it("also sees through wrappers and paths", () => {
    expect(matchDangerousCommand(["env", "X=1", "rm", "-rf", "build"])).toEqual(
      {
        description: "recursive force delete",
        pattern: "rm",
      },
    );
    expect(
      matchDangerousCommand(["/usr/bin/git", "reset", "--hard"])?.pattern,
    ).toBe("git");
  });
});
