import { configLoader } from "./loader";

/**
 * Apply pi's project trust decision to the shared loader at session start.
 * pi before 0.84.3 has no ctx.isProjectTrusted(); see setProjectTrusted.
 */
export function syncProjectTrust(ctx: {
  isProjectTrusted?: () => boolean;
  cwd?: string;
}): void {
  configLoader.setProjectTrusted(
    typeof ctx.isProjectTrusted === "function"
      ? ctx.isProjectTrusted()
      : undefined,
    ctx.cwd,
  );
}
