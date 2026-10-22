/**
 * Structural matcher for destructive or code-executing git commands.
 *
 * Works on the parsed, unquoted command words like the other built-in
 * matchers, so quoting (`--'force'`), git's long-option abbreviations
 * (`--forc`), grouped short flags (`-uf`), and refspec forms (`+main`,
 * `:old`) are all recognized.
 *
 * Goal is the same as the rest of the permission gate: catch accidents and
 * naive commands, and ask before they run. It is not a sandbox.
 */

type Words = readonly string[];

const MAX_BRACE_WORDS = 64;

/**
 * Expand `{a,b}` brace alternatives the way bash does before running the
 * command (`{+main,}` becomes `+main`). The shell parser keeps braces as
 * literal text, so without this `git push origin {+main,}` would hide the
 * refspec. Empty results are dropped, like bash drops empty words.
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
 * prefix abbreviations (`--forc`) and an `=value` suffix. Abbreviations that
 * would be ambiguous make git error out, so matching them is harmless.
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
 * the first letter in `stopAt`: that option takes a value, so the rest of
 * the word is its argument (`-ofoo`).
 */
function hasShortFlag(args: Words, flag: string, stopAt = ""): boolean {
  return args.some((word) => {
    if (!/^-[^-]/.test(word)) return false;
    for (const letter of word.slice(1)) {
      if (letter === flag) return true;
      if (stopAt.includes(letter)) return false;
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
  globals: string[];
  subcommand?: string;
  args: string[];
} {
  const globals: string[] = [];
  let i = 1;
  while (i < words.length) {
    const word = words[i] ?? "";
    if (!word.startsWith("-")) break;
    globals.push(word);
    if (GLOBAL_OPTIONS_WITH_VALUE.has(word)) {
      const value = words[i + 1];
      if (value !== undefined) globals.push(value);
      i += 2;
    } else {
      i += 1;
    }
  }
  return { globals, subcommand: words[i], args: words.slice(i + 1) };
}

function globalRisk(globals: Words): string | undefined {
  for (const word of globals) {
    if (word === "-c" || /^-c./.test(word)) {
      return "git -c config override (can run arbitrary commands)";
    }
    if (isLongOption(word, "config-env")) {
      return "git --config-env override (can run arbitrary commands)";
    }
    if (isLongOption(word, "exec-path") && word.includes("=")) {
      return "git --exec-path override (can run arbitrary commands)";
    }
  }
  return undefined;
}

const PUSH_SHORT_WITH_VALUE = "o";

function pushRisk(args: Words): string | undefined {
  if (hasLongOption(args, "receive-pack", "exec")) {
    return "git push with a custom receive-pack (runs a command)";
  }
  if (
    hasLongOption(args, "force", "force-with-lease", "force-if-includes") ||
    hasShortFlag(args, "f", PUSH_SHORT_WITH_VALUE)
  ) {
    return "git force push (rewrites remote history)";
  }
  const refs = operands(args).slice(1);
  if (refs.some((ref) => ref.startsWith("+") || ref.includes(":+"))) {
    return "git force push via +refspec (rewrites remote history)";
  }
  if (
    hasLongOption(args, "delete") ||
    hasShortFlag(args, "d", PUSH_SHORT_WITH_VALUE) ||
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

function uploadPackRisk(subcommand: string, args: Words): string | undefined {
  if (hasLongOption(args, "upload-pack")) {
    return `git ${subcommand} with a custom upload-pack (runs a command)`;
  }
  if (subcommand === "archive" && hasLongOption(args, "exec")) {
    return "git archive with a custom --exec (runs a command)";
  }
  // `-u <cmd>` is --upload-pack for these two (it means something else for
  // fetch and pull).
  if (
    (subcommand === "ls-remote" || subcommand === "clone") &&
    hasShortFlag(args, "u")
  ) {
    return `git ${subcommand} -u (custom upload-pack runs a command)`;
  }
  return undefined;
}

function branchRisk(args: Words): string | undefined {
  const deleting = hasLongOption(args, "delete") || hasShortFlag(args, "d");
  const forcing = hasLongOption(args, "force") || hasShortFlag(args, "f");
  if (hasShortFlag(args, "D") || (deleting && forcing)) {
    return "git branch force-delete (can lose unmerged commits)";
  }
  if (hasShortFlag(args, "M") || hasShortFlag(args, "C")) {
    return "git branch force rename/copy (overwrites an existing branch)";
  }
  return undefined;
}

function checkoutRisk(args: Words): string | undefined {
  if (hasLongOption(args, "force") || hasShortFlag(args, "f")) {
    return "git checkout --force (discards local changes)";
  }
  if (hasShortFlag(args, "B")) {
    return "git checkout -B (resets an existing branch)";
  }
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
    hasShortFlag(args, "f") ||
    hasShortFlag(args, "C")
  ) {
    return "git switch discarding changes or resetting a branch";
  }
  return undefined;
}

export function gitRisk(input: Words): string | undefined {
  if (input[0] !== "git") return undefined;
  const words = expandBraces(input);
  const { globals, subcommand, args } = splitGitCommand(words);

  const global = globalRisk(globals);
  if (global) return global;
  if (!subcommand) return undefined;

  switch (subcommand) {
    case "push":
      return pushRisk(args);
    case "fetch":
    case "pull":
    case "ls-remote":
    case "clone":
    case "archive":
      return uploadPackRisk(subcommand, args);
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
