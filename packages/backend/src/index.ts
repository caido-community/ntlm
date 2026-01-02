import { Buffer } from "buffer";

import type { DefineAPI, SDK } from "caido:plugin";
import { RequestSpec, type RequestSpecRaw } from "caido:utils";

import {
  createType1Message,
  createType3Message,
  decodeType2Message,
} from "./ntlm.js";

export type ConnectionInfo = {
  host: string;
  port: number;
  is_tls: boolean;
};

const generateRandomString = (sdk: SDK, length: number) => {
  const randomString = Math.random()
    .toString(36)
    .substring(2, length + 2);
  sdk.console.log(`Generating random string: ${randomString}`);
  return randomString;
};

const ntlm = async (sdk: SDK, request: RequestSpecRaw) => {
  try {
    const spec2 = request.toSpec();
    sdk.console.log(`Connecting to ${spec2.getUrl()}`);

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
    const type3Message = createType3Message(type2Message, "user", "password");

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
  generateRandomString: typeof generateRandomString;
}>;

export function init(sdk: SDK<API>) {
  sdk.api.register("generateRandomString", generateRandomString);
  sdk.events.onUpstream(ntlm);
}
