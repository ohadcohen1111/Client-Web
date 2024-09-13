import { createHeader } from './packetHeader';

export function createRegisterPacket(): Buffer {
  return createHeader(5); // Command 5 for ecRegister
}
