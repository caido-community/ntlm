import { Buffer } from "buffer";
import crypto from "crypto";

import {
  createLMHash,
  createLMResponse,
  createLMv2Response,
  createNTLMHash,
  createNTLMResponse,
  createNTLMv2Hash,
  createType2Message,
  decodeType1Message,
  decodeType2Message,
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
  type2Message?: NtlmType2Message;
} {
  const challenge = Buffer.from(
    Array.from({ length: 8 }, () => Math.floor(Math.random() * 256)),
  );

  const header = createType2Message({
    version,
    targetName: "DOMAIN",
    challenge,
  });

  if (version === 2) {
    const type2Message = decodeType2Message(header);
    return {
      header,
      challenge,
      type2Message,
    };
  }

  return { header, challenge };
}

export function parseType3(authHeader: string): NtlmType3Message | undefined {
  try {
    return decodeType3Message(authHeader);
  } catch {
    return undefined;
  }
}

function validateType3V1(
  type3: NtlmType3Message,
  challenge: Buffer,
  user: User,
): boolean {
  const ntlmHash = createNTLMHash(user.password);
  const expectedNtlm = createNTLMResponse(challenge, ntlmHash);

  if (type3.ntlmResponse.equals(expectedNtlm)) {
    return true;
  }

  const lmHash = createLMHash(user.password);
  const expectedLm = createLMResponse(challenge, lmHash);

  return type3.lmResponse.equals(expectedLm);
}

function validateType3V2(
  type3: NtlmType3Message,
  type2Message: NtlmType2Message,
  user: User,
): boolean {
  if (type3.lmResponse.length < 24) {
    return false;
  }

  if (!type2Message.targetInfo) {
    return false;
  }

  const ntlmHash = createNTLMHash(user.password);
  const targetName = type3.domain || type2Message.targetName;

  const clientNonce = type3.lmResponse.subarray(16, 24).toString("hex");

  const expectedLmv2 = createLMv2Response(
    type2Message,
    type3.username,
    ntlmHash,
    clientNonce,
    targetName,
  );

  if (!type3.lmResponse.equals(expectedLmv2)) {
    return false;
  }

  if (type3.ntlmResponse.length < 48) {
    return false;
  }

  const ntlm2hash = createNTLMv2Hash(ntlmHash, type3.username, targetName);
  const hmac = crypto.createHmac("md5", ntlm2hash);

  const validationBuf = Buffer.alloc(type3.ntlmResponse.length);
  type2Message.challenge.copy(validationBuf, 8);

  validationBuf.writeUInt32BE(0x01010000, 16);
  validationBuf.writeUInt32LE(0, 20);

  const timestampLow = type3.ntlmResponse.readUInt32LE(24);
  const timestampHigh = type3.ntlmResponse.readUInt32LE(28);
  validationBuf.writeUInt32LE(timestampLow, 24);
  validationBuf.writeUInt32LE(timestampHigh, 28);

  const ntlmv2Nonce = type3.ntlmResponse.subarray(32, 40);
  ntlmv2Nonce.copy(validationBuf, 32);

  validationBuf.writeUInt32LE(0, 40);

  const targetInfoStart = 44;
  const targetInfoLength = type3.ntlmResponse.length - targetInfoStart - 4;
  if (targetInfoLength > 0) {
    type3.ntlmResponse
      .subarray(targetInfoStart, targetInfoStart + targetInfoLength)
      .copy(validationBuf, targetInfoStart);
  }

  validationBuf.writeUInt32LE(0, validationBuf.length - 4);

  hmac.update(validationBuf.subarray(8));
  const expectedHmac = hmac.digest();
  const receivedHmac = type3.ntlmResponse.subarray(0, 16);

  return expectedHmac.equals(receivedHmac);
}

export function validateType3(
  type3: NtlmType3Message,
  challenge: Buffer,
  version: NtlmVersion,
  type2Message?: NtlmType2Message,
): User | undefined {
  const user = findUser(type3.username);
  if (!user) {
    return undefined;
  }

  if (version === 1) {
    return validateType3V1(type3, challenge, user) ? user : undefined;
  }

  if (version === 2) {
    if (!type2Message) {
      return undefined;
    }

    return validateType3V2(type3, type2Message, user) ? user : undefined;
  }

  return undefined;
}
