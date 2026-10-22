import { describe, expect, it } from "vitest";
import { checkDangerousCommand } from "./dangerous";
import { gitRisk } from "./git";

/** Run the full structural check (parser + built-in matchers). */
function check(command: string): string | undefined {
  return checkDangerousCommand({
    command,
    patterns: [],
    useBuiltinMatchers: true,
    fallbackPatterns: [],
  })?.description;
}

describe("git matcher", () => {
  describe("flags dangerous commands", () => {
    const dangerous: [string, RegExp][] = [
      // Force push: plain, quoted, abbreviated, grouped, lease, refspec.
      ["git push --force", /force push/],
      ["git push -f origin main", /force push/],
      ["git push -uf origin feat", /force push/],
      ["git push --'force'", /force push/],
      ["git push -'f' origin main", /force push/],
      ["git push --forc origin main", /force push/],
      ["git push --force-with-lease", /force push/],
      ["git push --force-with-lease=main:abc origin main", /force push/],
      ["git push origin +main", /\+refspec/],
      ["git push origin '+main'", /\+refspec/],
      ['git push origin "+main"', /\+refspec/],
      ["git push origin main:+main", /\+refspec/],
      ["git push origin {+main,}", /\+refspec/],
      ["git push -{f,} origin main", /force push/],
      ["git push origin {:old,}", /deleting a remote ref/],
      ["git -C /repo push origin +HEAD:main", /\+refspec/],
      // Remote ref deletion, mirror, prune.
      ["git push origin :old", /deleting a remote ref/],
      ["git push origin '':old", /deleting a remote ref/],
      ["git push origin --delete old", /deleting a remote ref/],
      ["git push --dele origin old", /deleting a remote ref/],
      ["git push -d origin old", /deleting a remote ref/],
      ["git push --mirror", /mirror/],
      ["git push --mirr", /mirror/],
      ["git push --prune origin", /prune/],
      // Commands run through git options.
      ["git push --receive-pac='x' . HEAD:x", /receive-pack/],
      ["git push --exec=x origin", /receive-pack/],
      ["git fetch --upload-pack='x;:' .", /upload-pack/],
      ["git fetch --upload-pac='x;:' .", /upload-pack/],
      ["git fetch --'upload-pack'=x .", /upload-pack/],
      ["git pull --upload-pa=x .", /upload-pack/],
      ["git ls-remote --upload-pack='x;:' .", /upload-pack/],
      ["git ls-remote -u 'x;:' .", /upload-pack/],
      ["git clone -u x https://example.com/r.git", /upload-pack/],
      ["git archive --remote=x --exec=y HEAD", /--exec/],
      ["git -c core.pager=x log", /-c config override/],
      ["git -ccore.pager=x log", /-c config override/],
      ["git --config-env=core.pager=X log", /--config-env/],
      ["git --exec-path=/tmp/x status", /--exec-path/],
      // Local destruction.
      ["git branch -D old", /force-delete/],
      ["git branch -'D' old", /force-delete/],
      ["git branch -d -f old", /force-delete/],
      ["git branch -df old", /force-delete/],
      ["git branch --delete --force old", /force-delete/],
      ["git branch --del --forc old", /force-delete/],
      ["git branch -M old new", /force rename/],
      ["git reset --hard", /reset --hard/],
      ["git reset --hard HEAD~1", /reset --hard/],
      ["git reset --har origin/main", /reset --hard/],
      ["git clean -fd", /clean -f/],
      ["git clean --force", /clean -f/],
      ["git checkout -- .", /checkout of paths/],
      ["git checkout .", /checkout of paths/],
      ["git checkout main -- src/a.ts", /checkout of paths/],
      ["git checkout -f main", /--force/],
      ["git checkout -b x --force", /--force/],
      ["git checkout -B main", /-B/],
      ["git checkout --theirs file.txt", /checkout of paths/],
      ["git restore src/a.ts", /restore/],
      ["git restore --staged --worktree src/a.ts", /restore/],
      ["git switch --discard-changes main", /switch/],
      ["git switch --discard main", /switch/],
      ["git switch -f main", /switch/],
      ["git switch -C main", /switch/],
      ["git stash drop", /stash drop/],
      ["git stash 'drop'", /stash drop/],
      ["git stash clear", /stash clear/],
      // Inside substitutions and chains (walker coverage).
      ["echo $(git push --force)", /force push/],
      ["git status && git reset --hard", /reset --hard/],
    ];
    for (const [command, description] of dangerous) {
      it(command, () => {
        expect(check(command)).toMatch(description);
      });
    }
  });

  describe("leaves everyday git alone", () => {
    const safe = [
      "git status",
      "git status -sb",
      "git -C /repo status",
      "git --no-pager log --oneline -5",
      "git log --format='%h %s' -10",
      "git log --follow -- src/a.ts",
      "git diff --stat",
      "git diff HEAD~1 -- src/a.ts",
      "git show HEAD:README.md",
      "git fetch origin",
      "git fetch -u origin",
      "git fetch --prune",
      "git pull --rebase",
      "git push",
      "git push origin main",
      "git push -u origin feat/x",
      "git push --follow-tags",
      "git push --tags",
      "git push origin HEAD:refs/heads/feat/x",
      "git push --no-force origin main",
      "git push --dry-run origin main",
      "git branch",
      "git branch -a -v",
      "git branch -d merged-branch",
      "git branch new-branch",
      "git add -A",
      "git commit -m 'source the env; git push --force is bad'",
      "git commit -F - <<'EOF'\nreset --hard is mentioned here\nEOF",
      "git stash",
      "git stash push -m 'wip'",
      "git stash pop",
      "git stash list",
      "git switch main",
      "git switch -c feat/x",
      "git checkout main",
      "git checkout -b feat/x origin/main",
      "git checkout -",
      "git restore --staged src/a.ts",
      "git reset --soft HEAD~1",
      "git reset src/a.ts",
      "git clean -n",
      "git ls-remote origin",
      "git clone https://example.com/r.git",
      "git remote -v",
    ];
    for (const command of safe) {
      it(command, () => {
        expect(check(command)).toBeUndefined();
      });
    }
  });

  it("ignores non-git commands", () => {
    expect(gitRisk(["ls", "--force"])).toBeUndefined();
    expect(gitRisk(["git"])).toBeUndefined();
  });
});
