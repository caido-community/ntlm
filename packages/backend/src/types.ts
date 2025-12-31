import type { Buffer, BufferEncoding } from "buffer";

export interface MessageType2 {
  flags?: any;
  encoding?: BufferEncoding;
  version?: number;
  challenge?: Buffer;
  targetName?: string;
  targetInfo?: any;
}
