import { PacketHeader } from './PacketHeader';

abstract class Packet {
  public header: PacketHeader; // Header field

  constructor(header: PacketHeader, public data: Uint8Array) {
    this.header = header; // Assign the header
  }

  abstract parseData(): void; // Abstract method to parse specific packet data
}

export default Packet;
