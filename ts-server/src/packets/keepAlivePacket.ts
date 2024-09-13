import { createHeader } from './packetHeader';

export function createKeepAlivePacket(bChannelAcquisition: boolean): Buffer {
  return createHeader(4); // Command 4 for ecKeepAlive
}
