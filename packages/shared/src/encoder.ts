import { Buffer } from "buffer";

import {
  NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,
  NTLMFLAG_NEGOTIATE_NTLM2_KEY,
  NTLMFLAG_NEGOTIATE_NTLM_KEY,
  NTLMFLAG_NEGOTIATE_OEM,
  NTLMFLAG_NEGOTIATE_TARGET_INFO,
  NTLMFLAG_REQUEST_TARGET,
  NTLMFLAG_TARGET_TYPE_DOMAIN,
} from "./flags.js";
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

export function createBasicMessage(user: string, pwd: string): string {
  return "Basic " + Buffer.from(user + ":" + pwd, "utf8").toString("base64");
}

export function createType1Message(
  workstation: string = "",
  target: string = "",
): string {
  let dataPos = 32;
  let pos = 0;
  const buf = Buffer.alloc(1024);

  buf.write(NTLM_SIGNATURE, pos, NTLM_SIGNATURE.length, "ascii");
  pos += NTLM_SIGNATURE.length;

  buf.writeUInt32LE(1, pos);
  pos += 4;

  buf.writeUInt32LE(
    NTLMFLAG_NEGOTIATE_OEM |
      NTLMFLAG_REQUEST_TARGET |
      NTLMFLAG_NEGOTIATE_NTLM_KEY |
      NTLMFLAG_NEGOTIATE_NTLM2_KEY |
      NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,
    pos,
  );
  pos += 4;

  buf.writeUInt16LE(target.length, pos);
  pos += 2;
  buf.writeUInt16LE(target.length, pos);
  pos += 2;
  buf.writeUInt32LE(target.length === 0 ? 0 : dataPos, pos);
  pos += 4;

  if (target.length > 0) {
    dataPos += buf.write(target, dataPos, "ascii");
  }

  buf.writeUInt16LE(workstation.length, pos);
  pos += 2;
  buf.writeUInt16LE(workstation.length, pos);
  pos += 2;
  buf.writeUInt32LE(workstation.length === 0 ? 0 : dataPos, pos);

  if (workstation.length > 0) {
    dataPos += buf.write(workstation, dataPos, "ascii");
  }

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

  buf.write(NTLM_SIGNATURE, pos, NTLM_SIGNATURE.length, "ascii");
  pos += NTLM_SIGNATURE.length;

  buf.writeUInt32LE(2, pos);
  pos += 4;

  let flags =
    NTLMFLAG_NEGOTIATE_OEM |
    NTLMFLAG_REQUEST_TARGET |
    NTLMFLAG_NEGOTIATE_NTLM_KEY |
    NTLMFLAG_TARGET_TYPE_DOMAIN;

  if (version === 2) {
    flags |= NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO;
  }

  const targetNameBytes = Buffer.from(targetName, "ascii");
  let dataPos = 56;

  buf.writeUInt16LE(targetNameBytes.length, pos);
  pos += 2;
  buf.writeUInt16LE(targetNameBytes.length, pos);
  pos += 2;
  buf.writeUInt32LE(dataPos, pos);
  pos += 4;

  buf.writeUInt32LE(flags, pos);
  pos += 4;

  const challengeBuffer =
    challenge ?? Buffer.from(createPseudoRandomValue(16), "hex");
  challengeBuffer.copy(buf, pos, 0, 8);
  pos += 8;

  buf.writeUInt32LE(0, pos);
  pos += 4;
  buf.writeUInt32LE(0, pos);
  pos += 4;

  let targetInfoBuffer: Buffer | undefined;
  if (version === 2) {
    const domainBytes = Buffer.from(targetName, "ucs2");
    const serverBytes = Buffer.from("SERVER", "ucs2");

    const targetInfoSize = 4 + domainBytes.length + 4 + serverBytes.length + 4;
    targetInfoBuffer = Buffer.alloc(targetInfoSize);
    let tiPos = 0;

    targetInfoBuffer.writeUInt16LE(2, tiPos);
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(domainBytes.length, tiPos);
    tiPos += 2;
    domainBytes.copy(targetInfoBuffer, tiPos);
    tiPos += domainBytes.length;

    targetInfoBuffer.writeUInt16LE(1, tiPos);
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(serverBytes.length, tiPos);
    tiPos += 2;
    serverBytes.copy(targetInfoBuffer, tiPos);
    tiPos += serverBytes.length;

    targetInfoBuffer.writeUInt16LE(0, tiPos);
    tiPos += 2;
    targetInfoBuffer.writeUInt16LE(0, tiPos);

    buf.writeUInt16LE(targetInfoBuffer.length, pos);
    pos += 2;
    buf.writeUInt16LE(targetInfoBuffer.length, pos);
    pos += 2;
    buf.writeUInt32LE(dataPos + targetNameBytes.length, pos);
    pos += 4;
  } else {
    buf.writeUInt16LE(0, pos);
    pos += 2;
    buf.writeUInt16LE(0, pos);
    pos += 2;
    buf.writeUInt32LE(0, pos);
    pos += 4;
  }

  targetNameBytes.copy(buf, dataPos);
  dataPos += targetNameBytes.length;

  if (targetInfoBuffer) {
    targetInfoBuffer.copy(buf, dataPos);
    dataPos += targetInfoBuffer.length;
  }

  return "NTLM " + buf.toString("base64", 0, dataPos);
}

export function createType3Message(
  type2Message: NtlmType2Message,
  username: string,
  password: string,
  workstation: string = "",
  target?: string,
): string {
  let dataPos = 52;
  const buf = Buffer.alloc(1024);

  const resolvedTarget = target ?? type2Message.targetName;

  buf.write(NTLM_SIGNATURE, 0, NTLM_SIGNATURE.length, "ascii");

  buf.writeUInt32LE(3, 8);

  if (type2Message.version === 2) {
    dataPos = 64;

    const ntlmHash = createNTLMHash(password);
    const nonce = createPseudoRandomValue(16);
    const lmv2 = createLMv2Response(
      type2Message,
      username,
      ntlmHash,
      nonce,
      resolvedTarget,
    );
    const ntlmv2 = createNTLMv2Response(
      type2Message,
      username,
      ntlmHash,
      nonce,
      resolvedTarget,
    );

    buf.writeUInt16LE(lmv2.length, 12);
    buf.writeUInt16LE(lmv2.length, 14);
    buf.writeUInt32LE(dataPos, 16);

    lmv2.copy(buf, dataPos);
    dataPos += lmv2.length;

    buf.writeUInt16LE(ntlmv2.length, 20);
    buf.writeUInt16LE(ntlmv2.length, 22);
    buf.writeUInt32LE(dataPos, 24);

    ntlmv2.copy(buf, dataPos);
    dataPos += ntlmv2.length;
  } else {
    const lmHash = createLMHash(password);
    const ntlmHash = createNTLMHash(password);
    const lm = createLMResponse(type2Message.challenge, lmHash);
    const ntlm = createNTLMResponse(type2Message.challenge, ntlmHash);

    buf.writeUInt16LE(lm.length, 12);
    buf.writeUInt16LE(lm.length, 14);
    buf.writeUInt32LE(dataPos, 16);

    lm.copy(buf, dataPos);
    dataPos += lm.length;

    buf.writeUInt16LE(ntlm.length, 20);
    buf.writeUInt16LE(ntlm.length, 22);
    buf.writeUInt32LE(dataPos, 24);

    ntlm.copy(buf, dataPos);
    dataPos += ntlm.length;
  }

  const targetLength =
    type2Message.encoding === "ascii"
      ? resolvedTarget.length
      : resolvedTarget.length * 2;
  buf.writeUInt16LE(targetLength, 28);
  buf.writeUInt16LE(targetLength, 30);
  buf.writeUInt32LE(dataPos, 32);

  dataPos += buf.write(resolvedTarget, dataPos, type2Message.encoding);

  const usernameLength =
    type2Message.encoding === "ascii" ? username.length : username.length * 2;
  buf.writeUInt16LE(usernameLength, 36);
  buf.writeUInt16LE(usernameLength, 38);
  buf.writeUInt32LE(dataPos, 40);

  dataPos += buf.write(username, dataPos, type2Message.encoding);

  const workstationLength =
    type2Message.encoding === "ascii"
      ? workstation.length
      : workstation.length * 2;
  buf.writeUInt16LE(workstationLength, 44);
  buf.writeUInt16LE(workstationLength, 46);
  buf.writeUInt32LE(dataPos, 48);

  dataPos += buf.write(workstation, dataPos, type2Message.encoding);

  if (type2Message.version === 2) {
    buf.writeUInt16LE(0, 52);
    buf.writeUInt16LE(0, 54);
    buf.writeUInt32LE(0, 56);

    buf.writeUInt32LE(type2Message.flags, 60);
  }

  return "NTLM " + buf.toString("base64", 0, dataPos);
}
