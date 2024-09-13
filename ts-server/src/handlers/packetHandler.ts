import dgram from 'dgram';
import { createRegisterPacket } from '../packets/registerPacket';
import { createKeepAlivePacket } from '../packets/keepAlivePacket';
import { parseCPacketAuthorize } from '../packets/authorizePacket';

const client = dgram.createSocket('udp4');

// Server details
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;

let previousCommand = 5; // ecRegister
let sequenceMinor = 0;

const servers = [{ ip: SERVER_IP, port: SERVER_PORT, id: null }];
let activeServerIndex = 0;

function handlePacket(msg: Buffer) {
  const command = (msg.readUInt8(22) >> 2) & 0x3F;
  if (command === 38) { // ecAuthorize
    const body = msg.slice(23);
    parseCPacketAuthorize(body, previousCommand);
  }
}

export function runClient() {
  client.on('message', (msg: Buffer) => {
    handlePacket(msg);
  });

  client.on('error', (err) => {
    console.error('UDP error:', err);
    client.close();
  });

  console.log('Sending initial Register packet...');
  const registerPacket = createRegisterPacket();
  client.send(registerPacket, SERVER_PORT, SERVER_IP);
  sequenceMinor++;

  setInterval(() => {
    const keepAlivePacket = createKeepAlivePacket(false);
    client.send(keepAlivePacket, SERVER_PORT, SERVER_IP);
  }, 7000); // Keep Alive every 7 seconds
}
