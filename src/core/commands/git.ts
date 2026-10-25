/**
 * Structural matcher for destructive git commands.
 *
 * Works on the parsed, unquoted command words like the other built-in
 * matchers, so quoting (`--'force'`), git's long-option abbreviations
 * (`--forc`), grouped short flags (`-uf`), simple brace alternatives
 * (`{+main,}`), and refspec forms (`+main`, `:old`) are recognized.
 *
 * Scope: operations that destroy work or rewrite/delete remote history. It
 * does not try to detect the many ways git can run other programs (hooks,
 * aliases, -c overrides); like the rest of the permission gate it catches
 * accidents and is not a sandbox.
 */

type Words = readonly string[];

const MAX_BRACE_WORDS = 64;

/**
 * Expand `{a,b}` alternatives the way bash does before running the command
 * (`{+main,}` becomes `+main`). The shell parser keeps braces as literal
 * text. Empty results are dropped, as bash drops empty words.
 */
function expandBraces(words: Words): string[] {
  const result: string[] = [];
  for (const word of words) {
    let variants = [word];
    for (let round = 0; round < 8; round++) {
      const next: string[] = [];
      let changed = false;
      for (const variant of variants) {
        const match = /\{([^{}]*,[^{}]*)\}/.exec(variant);
        if (!match) {
          next.push(variant);
          continue;
        }
        changed = true;
        const before = variant.slice(0, match.index);
        const after = variant.slice(match.index + match[0].length);
        for (const alternative of (match[1] ?? "").split(",")) {
          next.push(before + alternative + after);
        }
      }
      variants = next.slice(0, MAX_BRACE_WORDS);
      if (!changed) break;
    }
    result.push(...variants.filter((variant) => variant !== ""));
  }
  return result;
}

/** Global options that take a separate value: `git -C <dir> status`. */
const GLOBAL_OPTIONS_WITH_VALUE = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--super-prefix",
  "--config-env",
  "--exec-path",
  "--list-cmds",
  "--attr-source",
]);

/**
 * Whether `word` spells long option `--name`, including git's unambiguous
 * prefix abbreviations (`--forc`) and an `=value` suffix. An ambiguous
 * abbreviation makes git error out, so matching it is harmless.
 */
function isLongOption(word: string, name: string): boolean {
  if (!word.startsWith("--") || word === "--") return false;
  const spelled = word.slice(2).split("=", 1)[0] ?? "";
  return spelled.length > 0 && name.startsWith(spelled);
}

function hasLongOption(args: Words, ...names: string[]): boolean {
  return args.some((word) => names.some((name) => isLongOption(word, name)));
}

/**
 * Whether grouped short options (`-uf`) contain `flag`. Scanning stops at
 * the first letter in `takesValue`: that option consumes the rest of the
 * word as its argument (`-bfix` is `-b fix`, not `-b -f -i -x`).
 */
function hasShortFlag(args: Words, flag: string, takesValue = ""): boolean {
  return args.some((word) => {
    if (!/^-[^-]/.test(word)) return false;
    for (const letter of word.slice(1)) {
      if (letter === flag) return true;
      if (takesValue.includes(letter)) return false;
    }
    return false;
  });
}

/** Words that are not options. Everything after `--` is an operand. */
function operands(args: Words): string[] {
  const result: string[] = [];
  let afterDashDash = false;
  for (const word of args) {
    if (afterDashDash) result.push(word);
    else if (word === "--") afterDashDash = true;
    else if (!word.startsWith("-")) result.push(word);
  }
  return result;
}

/** Split `git [global options] <subcommand> [args]`. */
function splitGitCommand(words: Words): {
  subcommand?: string;
  args: string[];
} {
  let i = 1;
  while (i < words.length) {
    const word = words[i] ?? "";
    if (!word.startsWith("-")) break;
    i += GLOBAL_OPTIONS_WITH_VALUE.has(word) ? 2 : 1;
  }
  return { subcommand: words[i], args: words.slice(i + 1) };
}

// Short options that take a value, per subcommand (see git-<cmd>(1)).
const PUSH_VALUE = "o";
const BRANCH_VALUE = "u";
const CHECKOUT_VALUE = "bB";
const SWITCH_VALUE = "cC";

function pushRisk(args: Words): string | undefined {
  if (
    hasLongOption(args, "force", "force-with-lease", "force-if-includes") ||
    hasShortFlag(args, "f", PUSH_VALUE)
  ) {
    return "git force push (rewrites remote history)";
  }
  const refs = operands(args).slice(1);
  if (refs.some((ref) => ref.startsWith("+") || ref.includes(":+"))) {
    return "git force push via +refspec (rewrites remote history)";
  }
  if (
    hasLongOption(args, "delete") ||
    hasShortFlag(args, "d", PUSH_VALUE) ||
    refs.some((ref) => ref.startsWith(":") && ref.length > 1)
  ) {
    return "git push deleting a remote ref";
  }
  if (hasLongOption(args, "mirror")) {
    return "git push --mirror (overwrites and deletes remote refs)";
  }
  if (hasLongOption(args, "prune")) {
    return "git push --prune (deletes remote refs)";
  }
  return undefined;
}

function branchRisk(args: Words): string | undefined {
  const deleting =
    hasLongOption(args, "delete") || hasShortFlag(args, "d", BRANCH_VALUE);
  const forcing =
    hasLongOption(args, "force") || hasShortFlag(args, "f", BRANCH_VALUE);
  if (hasShortFlag(args, "D", BRANCH_VALUE) || (deleting && forcing)) {
    return "git branch force-delete (can lose unmerged commits)";
  }
  if (
    hasShortFlag(args, "M", BRANCH_VALUE) ||
    hasShortFlag(args, "C", BRANCH_VALUE)
  ) {
    return "git branch force rename/copy (overwrites an existing branch)";
  }
  // `git branch -f <name> <start>` moves an existing branch.
  if (forcing && operands(args).length >= 2) {
    return "git branch -f (resets an existing branch)";
  }
  return undefined;
}

function checkoutRisk(args: Words): string | undefined {
  if (hasLongOption(args, "force") || hasShortFlag(args, "f", CHECKOUT_VALUE)) {
    return "git checkout --force (discards local changes)";
  }
  if (hasShortFlag(args, "B", CHECKOUT_VALUE)) {
    return "git checkout -B (resets an existing branch)";
  }
  // `checkout <path>` without `--` is ambiguous with a branch name and is
  // not flagged.
  if (
    args.includes("--") ||
    operands(args).includes(".") ||
    hasLongOption(args, "ours", "theirs", "pathspec-from-file")
  ) {
    return "git checkout of paths (discards local changes)";
  }
  return undefined;
}

function restoreRisk(args: Words): string | undefined {
  const staged = hasLongOption(args, "staged") || hasShortFlag(args, "S");
  const worktree = hasLongOption(args, "worktree") || hasShortFlag(args, "W");
  // `--staged` alone only unstages; anything touching the worktree discards.
  if (staged && !worktree) return undefined;
  return "git restore (discards local changes)";
}

function switchRisk(args: Words): string | undefined {
  if (
    hasLongOption(args, "discard-changes", "force", "force-create") ||
    hasShortFlag(args, "f", SWITCH_VALUE) ||
    hasShortFlag(args, "C", SWITCH_VALUE)
  ) {
    return "git switch discarding changes or resetting a branch";
  }
  return undefined;
}

function worktreeRisk(args: Words): string | undefined {
  if (
    operands(args)[0] === "remove" &&
    (hasLongOption(args, "force") || hasShortFlag(args, "f"))
  ) {
    return "git worktree remove --force (discards changes in the worktree)";
  }
  return undefined;
}

export function gitRisk(input: Words): string | undefined {
  if (input[0] !== "git") return undefined;
  const { subcommand, args } = splitGitCommand(expandBraces(input));

  switch (subcommand) {
    case "push":
      return pushRisk(args);
    case "branch":
      return branchRisk(args);
    case "reset":
      return hasLongOption(args, "hard")
        ? "git reset --hard (discards local changes)"
        : undefined;
    case "clean":
      return hasLongOption(args, "force") || hasShortFlag(args, "f")
        ? "git clean -f (deletes untracked files)"
        : undefined;
    case "checkout":
      return checkoutRisk(args);
    case "restore":
      return restoreRisk(args);
    case "switch":
      return switchRisk(args);
    case "worktree":
      return worktreeRisk(args);
    case "stash": {
      const action = operands(args)[0];
      return action === "drop" || action === "clear"
        ? `git stash ${action} (deletes stashed changes)`
        : undefined;
    }
    default:
      return undefined;
  }
}
