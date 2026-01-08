import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";

import type { SDK } from "caido:plugin";

import type { NtlmConfig } from "./config.js";

const CONFIG_FILE_NAME = "ntlm-config.json";

export function getConfigPath(sdk: SDK): string {
  const pluginPath = sdk.meta.path();
  return join(pluginPath, CONFIG_FILE_NAME);
}

export async function loadConfig(sdk: SDK): Promise<NtlmConfig> {
  const configPath = getConfigPath(sdk);
  try {
    const data = await readFile(configPath, "utf-8");
    return JSON.parse(data) as NtlmConfig;
  } catch {
    return { rules: [] };
  }
}

export async function saveConfig(sdk: SDK, config: NtlmConfig): Promise<void> {
  const configPath = getConfigPath(sdk);
  const configDir = dirname(configPath);
  await mkdir(configDir, { recursive: true });
  const content = JSON.stringify(config, undefined, 2);
  await writeFile(configPath, content);
}
