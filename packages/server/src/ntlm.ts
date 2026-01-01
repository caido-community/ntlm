import { Buffer } from "buffer";

import {
  createLMHash,
  createLMResponse,
  createNTLMHash,
  createNTLMResponse,
  createType2Message,
  decodeType1Message,
  decodeType3Message,
  type NtlmType2Message,
  type NtlmType3Message,
  type NtlmVersion,
} from "shared";

import { findUser, type User } from "./credentials.js";

export type NtlmState = {
  stage: "initial" | "challenge_sent" | "authenticated";
  version: NtlmVersion;
  challenge?: Buffer;
  type2Message?: NtlmType2Message;
  user?: User;
};

export function parseType1(authHeader: string): { valid: boolean } {
  try {
    decodeType1Message(authHeader);
    return { valid: true };
  } catch {
    return { valid: false };
  }
}

export function generateType2(version: NtlmVersion): {
  header: string;
  challenge: Buffer;
} {
  const challenge = Buffer.from(
    Array.from({ length: 8 }, () => Math.floor(Math.random() * 256)),
  );

  const header = createType2Message({
    version,
    targetName: "DOMAIN",
    challenge,
  });

  return { header, challenge };
}

export function parseType3(authHeader: string): NtlmType3Message | undefined {
  try {
    return decodeType3Message(authHeader);
  } catch {
    return undefined;
  }
}

export function validateType3(
  type3: NtlmType3Message,
  challenge: Buffer,
  version: NtlmVersion,
): User | undefined {
  const user = findUser(type3.username);
  if (!user) {
    return undefined;
  }

  if (version === 1) {
    const ntlmHash = createNTLMHash(user.password);
    const expectedNtlm = createNTLMResponse(challenge, ntlmHash);

    if (type3.ntlmResponse.equals(expectedNtlm)) {
      return user;
    }

    const lmHash = createLMHash(user.password);
    const expectedLm = createLMResponse(challenge, lmHash);

    if (type3.lmResponse.equals(expectedLm)) {
      return user;
    }

    return undefined;
  }

  return user;
}
