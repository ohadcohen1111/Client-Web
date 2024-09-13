import { createHeader } from './packetHeader';
import { writeBits, writeString } from '../utils/bufferUtils';
import { readBits, readString } from '../utils/bufferUtils';
import { calcResponse } from '../utils/cryptoUtils';
import { base64Encode } from '../utils/cryptoUtils';

let sequenceMinor = 0;

/**
 * Create CPacketAuthorize packet
 */
export function createCPacketAuthorize(
  algorithm: number,
  authMethod: number,
  uri: string,
  realm: string,
  nonce: number,
  opaque: number,
  method: string,
  response: string,
  username: string,
  deviceId: number,
  passType: number
): Buffer {
  const buffer = Buffer.alloc(240);
  let offset = 0;
  let bitOffset = 0;

  writeBits(buffer, algorithm, 4, offset, bitOffset);
  writeBits(buffer, authMethod, 4, offset, bitOffset);
  writeString(buffer, uri, 63, offset);
  writeBits(buffer, 0, 8, offset, bitOffset); // RFU1
  writeString(buffer, realm, 63, offset);
  buffer.writeUInt32BE(nonce, offset);
  offset += 4;
  buffer.writeUInt32BE(opaque, offset);
  offset += 4;
  writeString(buffer, method, 16, offset);
  buffer.write(response, offset, 16, 'hex');
  offset += 16;
  writeString(buffer, username, 63, offset);
  buffer.writeBigUInt64BE(BigInt(deviceId), offset);
  offset += 8;
  writeBits(buffer, passType, 4, offset, bitOffset);

  const header = createHeader(38); // Command 38 for ecAuthorize
  return Buffer.concat([header, buffer]);
}

/**
 * Parse CPacketAuthorize packet
 */
export function parseCPacketAuthorize(buffer: Buffer, prevCommand: number): void {
  console.log(`Server -> Client: Received CPacketAuthorize (${buffer.length} bytes)`);

  let bitOffset = 0;
  const parsedPacket = {
    ALGORITHM: readBits(buffer, bitOffset, 4),
    AUTH_METHOD: readBits(buffer, bitOffset += 4, 4),
    URI: readString(buffer, bitOffset += 4, 504),
    RFU1: readBits(buffer, bitOffset += 504, 8),
    REALM: readString(buffer, bitOffset += 8, 504),
    NONCE: readBits(buffer, bitOffset += 504, 32),
    OPAQUE: readBits(buffer, bitOffset += 32, 32),
    METHOD: readString(buffer, bitOffset += 32, 128),
    RESPONSE: readString(buffer, bitOffset += 128, 128),
    USERNAME: readString(buffer, bitOffset += 128, 504),
    EAUTH_DEVICE_ID: readBits(buffer, bitOffset += 504, 64),
    EAUTH_PASS_TYPE: readBits(buffer, bitOffset += 64, 4),
  };

  // Convert NONCE to Base64
  const nonceBuffer = Buffer.alloc(4);
  nonceBuffer.writeUInt32BE(parsedPacket.NONCE);
  const base64Nonce = base64Encode(nonceBuffer);

  console.log('Parsed CPacketAuthorize:');
  for (const [key, value] of Object.entries(parsedPacket)) {
    if (key === 'NONCE') {
      console.log(`${key}: ${value} (${value.toString(16)}h) Base64: ${base64Nonce}`);
    } else if (typeof value === 'number') {
      console.log(`${key}: ${value} (${value.toString(16)}h)`);
    } else {
      console.log(`${key}: ${value}`);
    }
  }

  // Set username and password for response calculation
  const username = '999000000000075087';
  const password = '12345';
  const method = 'REGISTER'; // Example, adapt as needed

  // Calculate the response
  const response = calcResponse(username, parsedPacket.REALM, password, method, parsedPacket.URI, base64Nonce);

  console.log('Calculated Response:', response);
  console.log('Method used:', method);

  // Create and send the response packet
  const packetBody = createCPacketAuthorize(
    parsedPacket.ALGORITHM,
    parsedPacket.AUTH_METHOD,
    parsedPacket.URI,
    parsedPacket.REALM,
    parsedPacket.NONCE,
    parsedPacket.OPAQUE,
    method,
    response,
    username,
    parsedPacket.EAUTH_DEVICE_ID,
    parsedPacket.EAUTH_PASS_TYPE
  );

  sequenceMinor++;
  const header = createHeader(38); // Command 38 for ecAuthorize
  const fullPacket = Buffer.concat([header, packetBody]);

  console.log(`Client -> Server: Sending CPacketAuthorize (${fullPacket.length} bytes)`);
  // Implement your sendPacket function here to send fullPacket to the server
}
