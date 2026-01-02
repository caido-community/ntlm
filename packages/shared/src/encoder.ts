import { Buffer } from "buffer";

import * as flags from "./flags.js";
import {
  createLMHash,
  createLMResponse,
  createLMv2Response,
  createNTLMHash,
  createNTLMResponse,
  createNTLMv2Response,
  createPseudoRandomValue,
} from "./hash.js";
import { NTLM_SIGNATURE } from "./signature.js";
import type { NtlmType2Message, NtlmVersion } from "./types.js";

export function createType1Message(
  workstation: string = "",
  domain: string = "",
): string {
  let dataPos = 32;
  let pos = 0;
  const buf = Buffer.alloc(1024);

  // Protocol
  buf.write(NTLM_SIGNATURE, pos, NTLM_SIGNATURE.length, "ascii");
  pos += NTLM_SIGNATURE.length;

  // Message Type
  buf.writeUInt32LE(1, pos);
  pos += 4;

  // Flags
  // NOTE: Some implementations seem to send some more flags.
  // See https://github.com/SamDecrock/node-http-ntlm/blob/4ff6db8412808bb85467f418de76b8e490ccb3fb/ntlm.js#L48-L58
  buf.writeUInt32LE(
    flags.NTLMFLAG_NEGOTIATE_OEM |
      flags.NTLMFLAG_REQUEST_TARGET |
      flags.NTLMFLAG_NEGOTIATE_NTLM_KEY |
      flags.NTLMFLAG_NEGOTIATE_NTLM2_KEY |
      flags.NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,
    pos,
  );
  pos += 4;

  // Domain
  buf.writeUInt16LE(domain.length, pos); // Length
  pos += 2;
  buf.writeUInt16LE(domain.length, pos); // Max length
  pos += 2;
  buf.writeUInt32LE(domain.length === 0 ? 0 : dataPos, pos); // Data offset
  pos += 4;

  if (domain.length > 0) {
    dataPos += buf.write(domain, dataPos, "ascii"); // Write domain data
  }

  // Workstation
  buf.writeUInt16LE(workstation.length, pos); // Length
  pos += 2;
  buf.writeUInt16LE(workstation.length, pos); // Max length
  pos += 2;
  buf.writeUInt32LE(workstation.length === 0 ? 0 : dataPos, pos); // Data offset

  if (workstation.length > 0) {
    dataPos += buf.write(workstation, dataPos, "ascii"); // Write workstation data
  }

  // NOTE: Some implementations seem to send some more versions.
  // See https://github.com/SamDecrock/node-http-ntlm/blob/4ff6db8412808bb85467f418de76b8e490ccb3fb/ntlm.js#L101-L108

  return "NTLM " + buf.toString("base64", 0, dataPos);
}

export type CreateType2MessageOptions = {
  version: NtlmVersion;
  targetName?: string;
  challenge?: Buffer;
};

export function createType2Message(options: CreateType2MessageOptions): string {
  const { version, targetName = "DOMAIN", challenge } = options;

  const buf = Buffer.alloc(1024);
  let pos = 0;

  // Protocol
  buf.write(NTLM_SIGNATURE, pos, NTLM_SIGNATURE.length, "ascii");
  pos += NTLM_SIGNATURE.length;

  // Message Type
  buf.writeUInt32LE(2, pos);
  pos += 4;

  const targetNameBytes = Buffer.from(targetName, "ascii");
  let dataPos = 56;

  // Target Name
  buf.writeUInt16LE(targetNameBytes.length, pos); // Length
  pos += 2;
  buf.writeUInt16LE(targetNameBytes.length, pos); // Max length
  pos += 2;
  buf.writeUInt32LE(dataPos, pos); // Data offset
  pos += 4;

  // Flags
  let negotiateFlags =
    flags.NTLMFLAG_NEGOTIATE_OEM |
    flags.NTLMFLAG_REQUEST_TARGET |
    flags.NTLMFLAG_NEGOTIATE_NTLM_KEY |
    flags.NTLMFLAG_TARGET_TYPE_DOMAIN;

  if (version === 2) {
    negotiateFlags |=
      flags.NTLMFLAG_NEGOTIATE_NTLM2_KEY | flags.NTLMFLAG_NEGOTIATE_TARGET_INFO;
  }

  buf.writeUInt32LE(negotiateFlags, pos); // Negotiate flags
  pos += 4;

  // Challenge
  const challengeBuffer =
    challenge ?? Buffer.from(createPseudoRandomValue(16), "hex");
  challengeBuffer.copy(buf, pos, 0, 8); // Challenge
  pos += 8;

  buf.writeUInt32LE(0, pos); // Reserved
  pos += 4;
  buf.writeUInt32LE(0, pos); // Reserved
  pos += 4;

  // Target Info
  let targetInfoBuffer: Buffer | undefined;
  if (version === 2) {
    const domainBytes = Buffer.from(targetName, "utf16le");
    const serverBytes = Buffer.from("SERVER", "utf16le");

    const targetInfoSize = 4 + domainBytes.length + 4 + serverBytes.length + 4;
    targetInfoBuffer = Buffer.alloc(targetInfoSize);
    let tiPos = 0;

    targetInfoBuffer.writeUInt16LE(2, tiPos); // Domain name type
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(domainBytes.length, tiPos); // Domain name length
    tiPos += 2;
    domainBytes.copy(targetInfoBuffer, tiPos); // Domain name data
    tiPos += domainBytes.length;

    targetInfoBuffer.writeUInt16LE(1, tiPos); // Server name type
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(serverBytes.length, tiPos); // Server name length
    tiPos += 2;
    serverBytes.copy(targetInfoBuffer, tiPos); // Server name data
    tiPos += serverBytes.length;

    targetInfoBuffer.writeUInt16LE(0, tiPos); // Terminator type
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(0, tiPos); // Terminator length

    buf.writeUInt16LE(targetInfoBuffer.length, pos); // Length
    pos += 2;
    buf.writeUInt16LE(targetInfoBuffer.length, pos); // Max length
    pos += 2;
    buf.writeUInt32LE(dataPos + targetNameBytes.length, pos); // Data offset
    pos += 4;
  } else {
    buf.writeUInt16LE(0, pos); // Length
    pos += 2;
    buf.writeUInt16LE(0, pos); // Max length
    pos += 2;
    buf.writeUInt32LE(0, pos); // Data offset
    pos += 4;
  }

  targetNameBytes.copy(buf, dataPos); // Write target name data
  dataPos += targetNameBytes.length;

  if (targetInfoBuffer) {
    targetInfoBuffer.copy(buf, dataPos); // Write target info data
    dataPos += targetInfoBuffer.length;
  }

  return "NTLM " + buf.toString("base64", 0, dataPos);
}

export function createType3Message(
  type2Message: NtlmType2Message,
  username: string,
  password: string,
  workstation: string = "",
  domain?: string,
): string {
  let dataPos = 52;
  const buf = Buffer.alloc(1024);

  const resolvedDomain = domain ?? type2Message.targetName;

  // Protocol
  buf.write(NTLM_SIGNATURE, 0, NTLM_SIGNATURE.length, "ascii");

  // Message Type
  buf.writeUInt32LE(3, 8);

  if (type2Message.version === 2) {
    // NOTE: Some implementations seem to negotiate extended security.
    // See https://github.com/SamDecrock/node-http-ntlm/blob/4ff6db8412808bb85467f418de76b8e490ccb3fb/ntlm.js#L194
    dataPos = 64;
    const ntlmHash = createNTLMHash(password);
    const nonce = createPseudoRandomValue(16);

    // LMv2 security buffer
    const lmv2 = createLMv2Response(
      type2Message,
      username,
      ntlmHash,
      nonce,
      resolvedDomain,
    );

    buf.writeUInt16LE(lmv2.length, 12); // LM response length
    buf.writeUInt16LE(lmv2.length, 14); // LM response max length
    buf.writeUInt32LE(dataPos, 16); // LM response offset

    lmv2.copy(buf, dataPos); // Write LMv2 response data
    dataPos += lmv2.length;

    // NTLMv2 security buffer
    const ntlmv2 = createNTLMv2Response(
      type2Message,
      username,
      ntlmHash,
      nonce,
      resolvedDomain,
    );

    buf.writeUInt16LE(ntlmv2.length, 20); // NTLM response length
    buf.writeUInt16LE(ntlmv2.length, 22); // NTLM response max length
    buf.writeUInt32LE(dataPos, 24); // NTLM response offset

    ntlmv2.copy(buf, dataPos); // Write NTLMv2 response data
    dataPos += ntlmv2.length;
  } else {
    const lmHash = createLMHash(password);
    const ntlmHash = createNTLMHash(password);

    // LM security buffer
    const lm = createLMResponse(type2Message.challenge, lmHash);
    buf.writeUInt16LE(lm.length, 12); // LM response length
    buf.writeUInt16LE(lm.length, 14); // LM response max length
    buf.writeUInt32LE(dataPos, 16); // LM response offset

    lm.copy(buf, dataPos); // Write LM response data
    dataPos += lm.length;

    // NTLM security buffer
    const ntlm = createNTLMResponse(type2Message.challenge, ntlmHash);
    buf.writeUInt16LE(ntlm.length, 20); // NTLM response length
    buf.writeUInt16LE(ntlm.length, 22); // NTLM response max length
    buf.writeUInt32LE(dataPos, 24); // NTLM response offset

    ntlm.copy(buf, dataPos); // Write NTLM response data
    dataPos += ntlm.length;
  }

  // Domain
  const targetLength =
    type2Message.encoding === "ascii"
      ? resolvedDomain.length
      : resolvedDomain.length * 2;
  buf.writeUInt16LE(targetLength, 28); // Domain length
  buf.writeUInt16LE(targetLength, 30); // Domain max length
  buf.writeUInt32LE(dataPos, 32); // Domain offset

  dataPos += buf.write(resolvedDomain, dataPos, type2Message.encoding); // Write domain data

  // Username
  const usernameLength =
    type2Message.encoding === "ascii" ? username.length : username.length * 2;
  buf.writeUInt16LE(usernameLength, 36); // Username length
  buf.writeUInt16LE(usernameLength, 38); // Username max length
  buf.writeUInt32LE(dataPos, 40); // Username offset

  dataPos += buf.write(username, dataPos, type2Message.encoding); // Write username data

  // Workstation
  const workstationLength =
    type2Message.encoding === "ascii"
      ? workstation.length
      : workstation.length * 2;
  buf.writeUInt16LE(workstationLength, 44); // Workstation length
  buf.writeUInt16LE(workstationLength, 46); // Workstation max length
  buf.writeUInt32LE(dataPos, 48); // Workstation offset

  dataPos += buf.write(workstation, dataPos, type2Message.encoding); // Write workstation data

  // Session key
  if (type2Message.version === 2) {
    buf.writeUInt16LE(0, 52); // Session key length
    buf.writeUInt16LE(0, 54); // Session key max length
    buf.writeUInt32LE(0, 56); // Session key offset

    buf.writeUInt32LE(type2Message.flags, 60); // Flags
  }

  // NOTE: Some implementations seem to send some more flags.
  // See https://github.com/SamDecrock/node-http-ntlm/blob/4ff6db8412808bb85467f418de76b8e490ccb3fb/ntlm.js#L250-L253

  // NOTE: Some implementations seem to send versions
  // See https://github.com/SamDecrock/node-http-ntlm/blob/4ff6db8412808bb85467f418de76b8e490ccb3fb/ntlm.js#L255-L261

  return "NTLM " + buf.toString("base64", 0, dataPos);
}
