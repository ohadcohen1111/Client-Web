import { toBufferBE } from 'bigint-buffer';
import { ECommand } from '../utils';
import { username } from '../constants';

export class PacketHeader {
  private static lastHeader: PacketHeader | null = null;
  private static sequenceMajor: number = 0;
  private static sequenceMinor: number = 0;
  static readonly HEADER_SIZE: number = 23;
  private static readonly OLD_HEADER_LIMIT: ECommand = 63;
  
  constructor(
    public protocolVersion: number = 0x0200001C,
    public recipientId: bigint = 0n,
    public senderId: bigint = BigInt('0x' + BigInt(username.value).toString(16)),
    public sequenceMajor: number = 0,
    public sequenceMinor: number = 0,
    public command: ECommand
  ) { }

  static getNextHeader(command: ECommand): PacketHeader {
    if (!PacketHeader.lastHeader) {
      PacketHeader.lastHeader = new PacketHeader(undefined, undefined, undefined, 0, 0, command);
    } else {
      PacketHeader.sequenceMinor++;
      if (PacketHeader.sequenceMinor > 255 || PacketHeader.lastHeader.command == ECommand.ecAck) {
        PacketHeader.sequenceMinor = 0;
        PacketHeader.sequenceMajor = (PacketHeader.sequenceMajor + 1) % 256;
      }
      PacketHeader.lastHeader = new PacketHeader(
        PacketHeader.lastHeader.protocolVersion,
        PacketHeader.lastHeader.senderId,
        PacketHeader.lastHeader.recipientId,
        PacketHeader.sequenceMajor,
        PacketHeader.sequenceMinor,
        command
      );
    }
    return PacketHeader.lastHeader;
  }

  toBuffer(): Buffer {
    const buffer = Buffer.alloc(PacketHeader.HEADER_SIZE);
    buffer.writeUInt32BE(this.protocolVersion, 0);
    toBufferBE(this.recipientId, 8).copy(buffer, 4);
    toBufferBE(this.senderId, 8).copy(buffer, 12);
    buffer.writeUInt8(this.sequenceMajor, 20);
    buffer.writeUInt8(this.sequenceMinor, 21);
    buffer.writeUInt8((this.command < PacketHeader.OLD_HEADER_LIMIT ? this.command : PacketHeader.OLD_HEADER_LIMIT) << 2 | 0x1, 22);
    return buffer;
  }

  static fromBuffer(buffer: Buffer): PacketHeader {
    const command = buffer.readUInt8(22) >> 2;
    const header = new PacketHeader(
      buffer.readUInt32BE(0),
      buffer.readBigUInt64BE(4),
      buffer.readBigUInt64BE(12),
      buffer.readUInt8(20),
      buffer.readUInt8(21),
      command as ECommand
    );
    PacketHeader.lastHeader = header;
    PacketHeader.sequenceMajor = header.sequenceMajor;
    PacketHeader.sequenceMinor = header.sequenceMinor;
    return header;
  }

  static resetSequence() {
    PacketHeader.sequenceMajor = 0;
    PacketHeader.sequenceMinor = 0;
  }
}