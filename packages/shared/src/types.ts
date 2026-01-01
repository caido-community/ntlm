import type { Buffer } from "buffer";

export type NtlmEncoding = "ascii" | "ucs2";

export type NtlmVersion = 1 | 2;

export type NtlmTargetInfo = {
  parsed: {
    SERVER?: string;
    DOMAIN?: string;
    FQDN?: string;
    DNS?: string;
    PARENT_DNS?: string;
  };
  buffer: Buffer;
};

export type NtlmType1Message = {
  signature: string;
  messageType: 1;
  flags: number;
  domain: string;
  workstation: string;
};

export type NtlmType2Message = {
  signature: string;
  messageType: 2;
  flags: number;
  encoding: NtlmEncoding;
  version: NtlmVersion;
  challenge: Buffer;
  targetName: string;
  targetInfo?: NtlmTargetInfo;
};

export type NtlmType3Message = {
  signature: string;
  messageType: 3;
  lmResponse: Buffer;
  ntlmResponse: Buffer;
  domain: string;
  username: string;
  workstation: string;
  flags: number;
};
