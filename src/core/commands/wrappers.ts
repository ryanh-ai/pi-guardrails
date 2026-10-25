/**
 * Command-word normalization for the built-in dangerous-command matchers.
 *
 * A command can be run through a wrapper (`env FOO=1 git …`, `command rm …`,
 * `nice -n 5 git …`, `xargs git …`) or by path (`/usr/bin/git`). The
 * matchers compare `words[0]` against a command name, so they miss those
 * spellings. `commandLevels` returns the words as written, then each
 * unwrapped form, with the command word reduced to its basename.
 */

const MAX_DEPTH = 6;

function basename(word: string): string {
  const slash = word.lastIndexOf("/");
  return slash >= 0 && slash < word.length - 1 ? word.slice(slash + 1) : word;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface WrapperSpec {
  /** Options that take the next word as their value. */
  withValue: ReadonlySet<string>;
  /** Extra words to skip after the options (timeout's duration). */
  operands?: number;
  /** env: skip NAME=value words after the options. */
  assignments?: boolean;
  /** These options mean the wrapper does not run the command. */
  noRun?: ReadonlySet<string>;
}

const WRAPPERS: Record<string, WrapperSpec> = {
  command: { withValue: new Set(), noRun: new Set(["-v", "-V"]) },
  exec: { withValue: new Set(["-a"]) },
  nohup: { withValue: new Set() },
  nice: { withValue: new Set(["-n", "--adjustment"]) },
  env: {
    withValue: new Set(["-u", "--unset", "-C", "--chdir"]),
    assignments: true,
  },
  timeout: {
    withValue: new Set(["-s", "--signal", "-k", "--kill-after"]),
    operands: 1,
  },
  xargs: {
    withValue: new Set([
      "-a",
      "-d",
      "-E",
      "-I",
      "-L",
      "-n",
      "-P",
      "-s",
      "--arg-file",
      "--delimiter",
      "--eof",
      "--replace",
      "--max-lines",
      "--max-args",
      "--max-procs",
      "--max-chars",
      "--process-slot-var",
    ]),
  },
  stdbuf: {
    withValue: new Set(["-i", "-o", "-e", "--input", "--output", "--error"]),
  },
};

/** Words of the wrapped command, or undefined if `words` isn't a wrapper. */
function unwrapOnce(words: readonly string[]): string[] | undefined {
  const spec = WRAPPERS[basename(words[0] ?? "")];
  if (!spec) return undefined;

  let i = 1;
  while (i < words.length) {
    const word = words[i] ?? "";
    if (word === "--") {
      i++;
      break;
    }
    if (!word.startsWith("-") || word === "-") break;
    if (spec.noRun?.has(word)) return undefined;
    // `env -S "git push -f"` / `--split-string=...`: the value is the command.
    if (basename(words[0] ?? "") === "env") {
      const split =
        word === "-S" || word === "--split-string"
          ? words[i + 1]
          : word.startsWith("--split-string=")
            ? word.slice("--split-string=".length)
            : word.startsWith("-S") && word.length > 2
              ? word.slice(2)
              : undefined;
      if (split !== undefined) {
        const rest = word === "-S" || word === "--split-string" ? i + 2 : i + 1;
        return [...split.split(/\s+/).filter(Boolean), ...words.slice(rest)];
      }
    }
    i += spec.withValue.has(word) ? 2 : 1;
  }
  if (spec.assignments) {
    while (i < words.length && ASSIGNMENT.test(words[i] ?? "")) i++;
  }
  i += spec.operands ?? 0;

  const rest = words.slice(i);
  return rest.length > 0 ? rest : undefined;
}

/**
 * The command words as written, then each unwrapped level, with the command
 * word reduced to its basename. The first level is always the original
 * words, so a wrapper with its own matcher (sudo) is still matched.
 */
export function commandLevels(words: readonly string[]): string[][] {
  const levels: string[][] = [[...words]];
  let current: readonly string[] = words;
  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    const [head = "", ...rest] = current;
    const named = basename(head);
    if (named !== head) levels.push([named, ...rest]);
    const next = unwrapOnce(current);
    if (!next) break;
    levels.push(next);
    current = next;
  }
  return levels;
}
