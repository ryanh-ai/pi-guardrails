import { configLoader } from "../../src/shared/config";

interface NotifyContext {
  ui: { notify(message: string, type?: "info" | "warning" | "error"): void };
}

/**
 * Session-start notices for settings problems: unreadable files, project
 * settings ignored because the project is untrusted, and invalid values that
 * were dropped or fixed.
 */
export function notifyConfigHealth(ctx: NotifyContext): void {
  const files = configLoader.getFileStates();
  if (files.global?.state === "broken") {
    ctx.ui.notify(
      [
        `Guardrails: the global config can't be read (${files.global.reason}).`,
        `  ${files.global.path}`,
        "Running on built-in defaults: your custom rules are NOT active. Saving to this file is refused until it is fixed and pi is reloaded.",
      ].join("\n"),
      "error",
    );
  }
  if (files.local?.state === "broken") {
    ctx.ui.notify(
      `Guardrails: the project config can't be read and was skipped (${files.local.reason}).\n  ${files.local.path}`,
      "warning",
    );
  }

  const ignored = configLoader.getIgnoredLocalKeys();
  if (ignored.length > 0) {
    ctx.ui.notify(
      [
        "Guardrails: this project is not trusted, so project settings that would loosen protection are ignored:",
        ...ignored.map((key) => `- ${key}`),
        "To apply them, start pi in the project root and trust the project.",
      ].join("\n"),
      "warning",
    );
  }

  const shape = configLoader.getShapeIssues();
  for (const [scope, issues] of [
    ["global", shape.global],
    ["project", shape.local],
  ] as const) {
    if (issues.length === 0) continue;
    ctx.ui.notify(
      [
        `Guardrails: ignored or fixed invalid values in the ${scope} config:`,
        ...issues.map((issue) => `- ${issue}`),
      ].join("\n"),
      "warning",
    );
  }
}
