import { type Caido } from "@caido/sdk-frontend";
import type { API, NtlmConfig, RuleConfig } from "backend";

export type FrontendSDK = Caido<API, Record<string, never>>;

export type { NtlmConfig, RuleConfig };
