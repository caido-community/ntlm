import { Buffer } from "buffer";

import {
  NTLMFLAG_NEGOTIATE_NTLM2_KEY,
  NTLMFLAG_NEGOTIATE_OEM,
  NTLMFLAG_NEGOTIATE_TARGET_INFO,
} from "./flags.js";
import { NTLM_SIGNATURE } from "./signature.js";
import type {
  NtlmEncoding,
  NtlmTargetInfo,
  NtlmType1Message,
  NtlmType2Message,
  NtlmType3Message,
  NtlmVersion,
} from "./types.js";

function extractNtlmToken(authHeader: string): string {
  const ntlmMatch = /^NTLM ([^,\s]+)/.exec(authHeader);
  // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
  if (!ntlmMatch || !ntlmMatch[1]) {
    throw new Error("Couldn't find NTLM token in authorization header");
  }
  return ntlmMatch[1];
}

function validateSignature(buf: Buffer): void {
  if (buf.toString("ascii", 0, NTLM_SIGNATURE.length) !== NTLM_SIGNATURE) {
    throw new Error("Invalid NTLM message signature");
  }
}

export function decodeType1Message(authHeader: string): NtlmType1Message {
  const token = extractNtlmToken(authHeader);
  const buf = Buffer.from(token, "base64");

  validateSignature(buf);

  const messageType = buf.readUInt32LE(NTLM_SIGNATURE.length);
  if (messageType !== 1) {
    throw new Error(`Invalid message type: expected 1, got ${messageType}`);
  }

  const flags = buf.readUInt32LE(12);

  const domainLength = buf.readUInt16LE(16);
  const domainOffset = buf.readUInt32LE(20);

  const workstationLength = buf.readUInt16LE(24);
  const workstationOffset = buf.readUInt32LE(28);

  const domain =
    domainLength > 0
      ? buf.toString("ascii", domainOffset, domainOffset + domainLength)
      : "";

  const workstation =
    workstationLength > 0
      ? buf.toString(
          "ascii",
          workstationOffset,
          workstationOffset + workstationLength,
        )
      : "";

  return {
    signature: NTLM_SIGNATURE,
    messageType: 1,
    flags,
    domain,
    workstation,
  };
}

export function decodeType2Message(authHeader: string): NtlmType2Message {
  const token = extractNtlmToken(authHeader);
  const buf = Buffer.from(token, "base64");

  validateSignature(buf);

  const messageType = buf.readUInt32LE(NTLM_SIGNATURE.length);
  if (messageType !== 2) {
    throw new Error(`Invalid message type: expected 2, got ${messageType}`);
  }

  // Flags
  const flags = buf.readUInt32LE(20);
  const encoding: NtlmEncoding =
    flags & NTLMFLAG_NEGOTIATE_OEM ? "ascii" : "utf16le";
  const version: NtlmVersion = flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY ? 2 : 1;

  // Challenge
  const challenge = Buffer.alloc(8);
  buf.copy(challenge, 0, 24, 32);

  // Target Name
  let targetName = "";
  const targetNameLength = buf.readUInt16LE(12);
  const targetNameOffset = buf.readUInt32LE(16);
  if (targetNameLength > 0) {
    if (
      targetNameOffset + targetNameLength > buf.length ||
      targetNameOffset < 32
    ) {
      throw new Error("Bad type 2 message: invalid target name offset");
    }
    targetName = buf.toString(
      encoding,
      targetNameOffset,
      targetNameOffset + targetNameLength,
    );
  }

  // Target Info
  let targetInfo: NtlmTargetInfo | undefined;
  if (flags & NTLMFLAG_NEGOTIATE_TARGET_INFO) {
    const targetInfoLength = buf.readUInt16LE(40);
    const targetInfoOffset = buf.readUInt32LE(44);

    if (targetInfoLength > 0) {
      if (
        targetInfoOffset + targetInfoLength > buf.length ||
        targetInfoOffset < 32
      ) {
        throw new Error("Bad type 2 message: invalid target info offset");
      }

      const targetInfoBuffer = Buffer.alloc(targetInfoLength);
      buf.copy(
        targetInfoBuffer,
        0,
        targetInfoOffset,
        targetInfoOffset + targetInfoLength,
      );

      const parsed: NtlmTargetInfo["parsed"] = {};
      let pos = targetInfoOffset;

      while (pos < targetInfoOffset + targetInfoLength) {
        const blockType = buf.readUInt16LE(pos);
        pos += 2;
        const blockLength = buf.readUInt16LE(pos);
        pos += 2;

        if (blockType === 0) {
          break;
        }

        const blockValue = buf.toString("utf16le", pos, pos + blockLength);

        switch (blockType) {
          case 1:
            parsed.SERVER = blockValue;
            break;
          case 2:
            parsed.DOMAIN = blockValue;
            break;
          case 3:
            parsed.FQDN = blockValue;
            break;
          case 4:
            parsed.DNS = blockValue;
            break;
          case 5:
            parsed.PARENT_DNS = blockValue;
            break;
        }

        pos += blockLength;
      }

      targetInfo = {
        parsed,
        buffer: targetInfoBuffer,
      };
    }
  }

  return {
    signature: NTLM_SIGNATURE,
    messageType: 2,
    flags,
    encoding,
    version,
    challenge,
    targetName,
    targetInfo,
  };
}

export type DecodeType3MessageOptions = {
  encoding: NtlmEncoding;
  version: NtlmVersion;
};

export function decodeType3Message(
  authHeader: string,
  options: DecodeType3MessageOptions,
): NtlmType3Message {
  const token = extractNtlmToken(authHeader);
  const buf = Buffer.from(token, "base64");

  validateSignature(buf);

  const messageType = buf.readUInt32LE(NTLM_SIGNATURE.length);
  if (messageType !== 3) {
    throw new Error(`Invalid message type: expected 3, got ${messageType}`);
  }

  const lmResponseLength = buf.readUInt16LE(12);
  const lmResponseOffset = buf.readUInt32LE(16);
  const lmResponse = Buffer.alloc(lmResponseLength);
  buf.copy(
    lmResponse,
    0,
    lmResponseOffset,
    lmResponseOffset + lmResponseLength,
  );

  const ntlmResponseLength = buf.readUInt16LE(20);
  const ntlmResponseOffset = buf.readUInt32LE(24);
  const ntlmResponse = Buffer.alloc(ntlmResponseLength);
  buf.copy(
    ntlmResponse,
    0,
    ntlmResponseOffset,
    ntlmResponseOffset + ntlmResponseLength,
  );

  const domainLength = buf.readUInt16LE(28);
  const domainOffset = buf.readUInt32LE(32);

  const usernameLength = buf.readUInt16LE(36);
  const usernameOffset = buf.readUInt32LE(40);

  const workstationLength = buf.readUInt16LE(44);
  const workstationOffset = buf.readUInt32LE(48);

  let flags = 0;
  if (options.version === 2) {
    buf.readUInt16LE(52);
    buf.readUInt16LE(54);
    buf.readUInt32LE(56);

    if (buf.length >= 64) {
      flags = buf.readUInt32LE(60);
    }
  } else {
    if (buf.length >= 64) {
      flags = buf.readUInt32LE(60);
    }
  }

  const domain =
    domainLength > 0
      ? buf.toString(
          options.encoding,
          domainOffset,
          domainOffset + domainLength,
        )
      : "";

  const username =
    usernameLength > 0
      ? buf.toString(
          options.encoding,
          usernameOffset,
          usernameOffset + usernameLength,
        )
      : "";

  const workstation =
    workstationLength > 0
      ? buf.toString(
          options.encoding,
          workstationOffset,
          workstationOffset + workstationLength,
        )
      : "";

  return {
    signature: NTLM_SIGNATURE,
    messageType: 3,
    lmResponse,
    ntlmResponse,
    domain,
    username,
    workstation,
    flags,
  };
}
