export { DEFAULT_CONFIG } from "./defaults";
export { configLoader, syncProjectTrust } from "./loader";
export { globalConfigMigrations, migrations } from "./migration";
export type {
  AllowedPath,
  DangerousPattern,
  GuardrailsConfig,
  PathAccessConfig,
  PathAccessMode,
  PatternConfig,
  PolicyRule,
  Protection,
  ResolvedConfig,
} from "./types";
