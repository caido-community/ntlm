import type { RawConfigurationOrFn } from "knip/dist/types/config.js";

const config: RawConfigurationOrFn = {
  workspaces: {
    ".": {
      entry: ["caido.config.ts", "eslint.config.mjs"],
      ignoreBinaries: ["dev"],
    },
    "packages/backend": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido"],
    },
    "packages/frontend": {
      entry: ["src/index.ts"],
      project: ["src/**/*.{ts,tsx,vue}"],
    },
    "packages/server": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
    },
  },
  ignoreIssues: {
    "packages/server/src/credentials.ts": ["exports", "types"],
    "packages/server/package.json": ["dependencies"],
  },
};

export default config;
