export { DEFAULT_CONFIG } from "./defaults";
export {
  addTrustedProjectGrant,
  type ConfigFileState,
  type ConfigHealth,
  type GlobalConfigMode,
  projectKey,
} from "./health";
export { configLoader } from "./loader";
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
