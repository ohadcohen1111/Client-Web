import { toBufferBE } from 'bigint-buffer';

let sequenceMinor = 0;

export function createHeader(command: number): Buffer {
  const header = Buffer.alloc(23);
  header.writeUInt32BE(0x0200001C, 0); // Protocol version
  toBufferBE(BigInt(0x0000000000000000), 8).copy(header, 4); // Recipient ID
  toBufferBE(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12); // Sender ID
  header.writeUInt8(0, 20); // Sequence (major)
  header.writeUInt8(sequenceMinor, 21); // Sequence (minor)
  header.writeUInt8((command << 2) | 0x0, 22); // Command + Flags
  sequenceMinor++;
  return header;
}
