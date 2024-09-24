import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

abstract class Packet {
  public header: PacketHeader;

  constructor(command: ECommand, header?: PacketHeader, public data?: Uint8Array) {
    switch (command) {
      // to not increase the header
      case ECommand.ecApproved:
        //case ...
        this.header = header!;
        return;
    }

    this.header = PacketHeader.getNextHeader(command);
  }

  abstract parseData(): void;
  abstract toBuffer(): Buffer;
}

export { Packet }