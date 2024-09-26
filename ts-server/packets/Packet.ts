import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

abstract class Packet {
  public header: PacketHeader;

  constructor(command: ECommand, header?: PacketHeader, public data?: Uint8Array, isNewHeaderNeeded: boolean = true) {
    if (isNewHeaderNeeded) {
      this.header = PacketHeader.getNextHeader(command);
    }
    else {
      this.header = header!;
    }
  }

  abstract parseData(): void;
  abstract toBuffer(): Buffer;
}

export { Packet }