import { Buffer } from "buffer";

import type { DefineAPI, SDK } from "caido:plugin";
import { RequestSpec, type RequestSpecRaw } from "caido:utils";

import type { NtlmConfig, RuleConfig } from "./config.js";
import {
  createType1Message,
  createType3Message,
  decodeType2Message,
} from "./ntlm.js";
import { Rule as NtlmRule } from "./server.js";
import { loadConfig, saveConfig } from "./store.js";

export type ConnectionInfo = {
  host: string;
  port: number;
  is_tls: boolean;
};

let config: NtlmConfig = { rules: [] };
let rules: NtlmRule[] = [];

function getConfig(sdk: SDK): NtlmConfig {
  return config;
}

async function saveConfigAPI(sdk: SDK, newConfig: NtlmConfig): Promise<void> {
  config = newConfig;
  rules = config.rules
    .filter((ruleConfig) => ruleConfig.enabled === true)
    .map((ruleConfig: RuleConfig) => new NtlmRule(ruleConfig));
  await saveConfig(sdk, config);
}

const ntlm = async (sdk: SDK, request: RequestSpecRaw) => {
  try {
    const spec2 = request.toSpec();
    const domain = request.getHost();
    sdk.console.log(`Connecting to ${spec2.getUrl()}`);

    let matchingRule: NtlmRule | undefined = undefined;
    for (const rule of rules) {
      if (rule.matches(domain) === true) {
        matchingRule = rule;
        break;
      }
    }

    if (matchingRule === undefined) {
      sdk.console.log(`No matching rule configuration for domain: ${domain}`);
      return undefined;
    }

    const credentials = matchingRule.getCredentials();
    sdk.console.log(`Using rule configuration: ${matchingRule.getName()}`);

    // Send the type 1 message
    const type1Message = createType1Message("", "");
    sdk.console.log(`Sending type 1 message: ${type1Message}`);
    const spec = new RequestSpec(spec2.getUrl());
    spec.setMethod(spec2.getMethod());
    spec.setHeader("Host", `${request.getHost()}:${request.getPort()}`);
    spec.setHeader("Connection", "keep-alive");
    spec.setHeader("Authorization", type1Message);
    sdk.console.log(
      `Sending request: ${Buffer.from(spec.getRaw().getRaw()).toString(
        "ascii",
      )}`,
    );
    const { response, connection } = await sdk.requests.send(spec);

    sdk.console.log(`Response: ${response.getRaw()?.toText()}`);

    // Decode the type 2 message
    const wwwAuthenticate = response.getHeader("WWW-Authenticate")![0]!;
    sdk.console.log(`Type 2 message received, header: ${wwwAuthenticate}`);
    const type2Message = decodeType2Message(wwwAuthenticate);

    // Create the type 3 message
    sdk.console.log(`Creating type 3 message`);
    const type3Message = createType3Message(
      type2Message,
      credentials.username,
      credentials.password,
    );

    // Send the type 3 message
    sdk.console.log(`Setting authorization header: ${type3Message}`);

    spec2.setHeader("Authorization", type3Message);
    spec2.setHeader("Connection", "Close");
    sdk.console.log(
      `Sending request: ${Buffer.from(spec2.getRaw().getRaw()).toString(
        "ascii",
      )}`,
    );

    return {
      connection,
      request: spec2,
    };
  } catch (error) {
    sdk.console.error(error);
    return undefined;
  }
};

export type API = DefineAPI<{
  getConfig: typeof getConfig;
  saveConfig: typeof saveConfigAPI;
}>;

export type { CredentialSet, NtlmConfig, RuleConfig } from "./config.js";

export async function init(sdk: SDK<API>) {
  config = await loadConfig(sdk);
  rules = config.rules
    .filter((ruleConfig) => ruleConfig.enabled === true)
    .map((ruleConfig: RuleConfig) => new NtlmRule(ruleConfig));

  sdk.api.register("getConfig", getConfig);
  sdk.api.register("saveConfig", saveConfigAPI);
  sdk.events.onUpstream(ntlm);
}
