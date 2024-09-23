import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

abstract class Packet {
  public header: PacketHeader;

  constructor(command: ECommand, header?: PacketHeader, public data?: Uint8Array) {
    this.header = PacketHeader.getNextHeader(command);
  }

  abstract parseData(): void;
  abstract toBuffer(): Buffer;
}

export { Packet }