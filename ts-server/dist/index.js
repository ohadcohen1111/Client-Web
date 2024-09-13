"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dgram_1 = __importDefault(require("dgram"));
const bigint_buffer_1 = require("bigint-buffer");
const crypto_1 = __importDefault(require("crypto"));
const client = dgram_1.default.createSocket('udp4');
// Server details
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;
// Command constants
const COMMAND_AUTHORIZE = 38;
const COMMAND_REGISTER = 5;
const COMMAND_ACK = 1;
let previousCommand = 5; // Assuming initial command is ecRegister (5)
let sequenceMinor = 0;
const servers = [{ ip: SERVER_IP, port: SERVER_PORT, id: null }];
let activeServerIndex = 0;
let numServerToggles = 0;
let lastTxTime = 0;
let isDormant = false;
/**
 * Custom Base64 encoding function
 */
function base64Encode(srcBuffer) {
    const cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const dest = [];
    let i = 0;
    while (i < srcBuffer.length) {
        const byte0 = srcBuffer[i];
        const byte1 = i + 1 < srcBuffer.length ? srcBuffer[i + 1] : 0;
        const byte2 = i + 2 < srcBuffer.length ? srcBuffer[i + 2] : 0;
        dest.push(cvt[byte0 & 0x3F], cvt[(byte0 >> 6) | ((byte1 & 0x0F) << 2)], i + 1 < srcBuffer.length ? cvt[(byte1 >> 4) | ((byte2 & 0x03) << 4)] : '=', i + 2 < srcBuffer.length ? cvt[byte2 >> 2] : '=');
        i += 3;
    }
    return dest.join('');
}
/**
 * Helper function to read specific bits from a buffer
 */
function readBits(buffer, bitOffset, numBits) {
    const binaryString = buffer.toString('binary').split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    return parseInt(binaryString.substr(bitOffset, numBits), 2);
}
/**
 * Helper function to read a string of bits
 */
function readString(buffer, bitOffset, numBits) {
    let str = '';
    for (let i = 0; i < numBits; i += 8) {
        const charCode = readBits(buffer, bitOffset + i, 8);
        if (charCode !== 0) {
            str += String.fromCharCode(charCode);
        }
    }
    return str.trim();
}
/**
 * Calculate MD5 hash
 */
function calcMD5(input) {
    return crypto_1.default.createHash('md5').update(input).digest('hex');
}
/**
 * Calculate the response for authorization
 */
function calcResponse(username, realm, password, method, uri, nonce) {
    const ha1 = calcMD5(`${username}:${realm}:${password}`);
    const ha2 = calcMD5(`${method}:${uri}`);
    return calcMD5(`${ha1}:${nonce}:${ha2}`);
}
/**
 * Get SIP method based on the command
 */
function GetSIPMethod(cmd) {
    switch (cmd) {
        case 1:
        case 3:
        case 4:
            return "ACK";
        case 38:
        case 39:
            return "FORBIDDEN";
        case 5:
        case 6:
        case 7:
            return "REGISTER";
        case 7:
            return "APPROVED";
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            return "INVITE";
        case 16:
        case 17:
            return "BYE";
        case 21:
        case 22:
            return "SUBSCRIBE";
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
            return "NOTIFY";
        case 31:
        case 32:
        case 33:
        case 34:
        case 35:
        case 36:
            return "INFO";
        default:
            return "ERROR";
    }
}
/**
 * Create header for packets
 */
function createHeader(command) {
    const header = Buffer.alloc(23);
    header.writeUInt32BE(0x0200001C, 0); // Protocol version
    (0, bigint_buffer_1.toBufferBE)(BigInt(0x0000000000000000), 8).copy(header, 4); // Recipient ID
    (0, bigint_buffer_1.toBufferBE)(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12); // Sender ID
    header.writeUInt8(0, 20); // Sequence (major)
    header.writeUInt8(sequenceMinor, 21); // Sequence (minor)
    header.writeUInt8((command << 2) | 0x0, 22); // Command + Flags
    return header;
}
/**
 * Create CPacketAuthorize packet
 */
function createCPacketAuthorize(algorithm, authMethod, uri, realm, nonce, opaque, method, response, username, deviceId, passType) {
    const buffer = Buffer.alloc(240);
    let offset = 0;
    let bitOffset = 0;
    function writeBits(value, bits) {
        while (bits > 0) {
            const availableBits = 8 - (bitOffset % 8);
            const bitsToWrite = Math.min(availableBits, bits);
            const mask = (1 << bitsToWrite) - 1;
            const shiftedValue = (value & mask) << (availableBits - bitsToWrite);
            buffer[offset] |= shiftedValue;
            value >>= bitsToWrite;
            bits -= bitsToWrite;
            bitOffset += bitsToWrite;
            if (bitOffset % 8 === 0) {
                offset++;
            }
        }
    }
    function writeString(str, maxBytes) {
        const buf = Buffer.from(str, 'utf8');
        buf.copy(buffer, offset, 0, Math.min(buf.length, maxBytes));
        offset += maxBytes;
        bitOffset = offset * 8;
    }
    writeBits(algorithm, 4);
    writeBits(authMethod, 4);
    writeString(uri, 63);
    writeBits(0, 8); // RFU1
    writeString(realm, 63);
    buffer.writeUInt32BE(nonce, offset);
    offset += 4;
    bitOffset = offset * 8;
    buffer.writeUInt32BE(opaque, offset);
    offset += 4;
    bitOffset = offset * 8;
    writeString(method, 16);
    buffer.write(response, offset, 16, 'hex');
    offset += 16;
    bitOffset = offset * 8;
    writeString(username, 63);
    buffer.writeBigUInt64BE(BigInt(deviceId), offset);
    offset += 8;
    bitOffset = offset * 8;
    writeBits(passType, 4);
    return buffer;
}
/**
 * Handle incoming packets
 */
function handlePacket(msg) {
    const command = (msg.readUInt8(22) >> 2) & 0x3F;
    console.log(`Received packet: Command ${command} (${msg.length} bytes)`);
    if (command === COMMAND_AUTHORIZE) {
        console.log('Received ecAuthorize packet');
        const body = msg.slice(23); // The body starts after the 23-byte header
        parseCPacketAuthorize(body, previousCommand);
    }
    else if (command === COMMAND_ACK) {
        console.log('Received ACK packet');
        handleAckPacket(msg);
    }
    else {
        console.log(`Received command: ${command}`);
        previousCommand = command; // Update the previous command
    }
}
// Additional functions (parseCPacketAuthorize, handleAckPacket, etc.) go here
/**
 * Parse CPacketAuthorize packet
 */
function parseCPacketAuthorize(buffer, prevCommand) {
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
        EAUTH_PASS_TYPE: readBits(buffer, bitOffset += 64, 4)
    };
    // Convert NONCE to Base64
    const nonceBuffer = Buffer.alloc(4);
    nonceBuffer.writeUInt32BE(parsedPacket.NONCE);
    const base64Nonce = base64Encode(nonceBuffer);
    console.log('Parsed CPacketAuthorize:');
    for (const [key, value] of Object.entries(parsedPacket)) {
        if (key === 'NONCE') {
            console.log(`${key}: ${value} (${value.toString(16)}h) Base64: ${base64Nonce}`);
        }
        else if (typeof value === 'number') {
            console.log(`${key}: ${value} (${value.toString(16)}h)`);
        }
        else {
            console.log(`${key}: ${value}`);
        }
    }
    // Set username and password for response calculation
    const username = "999000000000075087";
    const password = "12345";
    const method = GetSIPMethod(prevCommand || 0);
    // Calculate the response
    const response = calcResponse(username, parsedPacket.REALM, password, method, parsedPacket.URI, base64Nonce);
    console.log('Calculated Response:', response);
    console.log('Method used:', method);
    // Create and send the response packet
    const packetBody = createCPacketAuthorize(parsedPacket.ALGORITHM, parsedPacket.AUTH_METHOD, parsedPacket.URI, parsedPacket.REALM, parsedPacket.NONCE, parsedPacket.OPAQUE, method, response, username, parsedPacket.EAUTH_DEVICE_ID, parsedPacket.EAUTH_PASS_TYPE);
    sequenceMinor++;
    const header = createHeader(COMMAND_AUTHORIZE);
    const fullPacket = Buffer.concat([header, packetBody]);
    console.log(`Client -> Server: Sending CPacketAuthorize (${fullPacket.length} bytes)`);
    sendPacket(fullPacket);
}
/**
 * Handle ACK packet
 */
function handleAckPacket(packet) {
    if (previousCommand === COMMAND_REGISTER) {
        console.log('Received immediate ACK after registration');
        const isSecondaryMode = false;
        const isDualSystem = false;
        if (isSecondaryMode || isDualSystem) {
            console.log('Switching server due to secondary mode or dual system');
            switchServer();
        }
    }
}
/**
 * Switch to the next server
 */
function switchServer() {
    if (servers.length > 1) {
        activeServerIndex = (activeServerIndex + 1) % servers.length;
        numServerToggles++;
        console.log(`Switched to server: ${servers[activeServerIndex].ip}:${servers[activeServerIndex].port}`);
        sendKeepAlive();
    }
    else {
        console.log('No alternative servers available');
    }
}
/**
 * Send a packet to the active server
 */
function sendPacket(packet) {
    const currentServer = servers[activeServerIndex];
    client.send(packet, currentServer.port, currentServer.ip, (err) => {
        if (err) {
            console.error('Error sending packet:', err);
        }
        else {
            console.log(`Packet sent to ${currentServer.ip}:${currentServer.port}`);
            lastTxTime = Date.now();
        }
    });
}
/**
 * Send Keep Alive packet
 */
function sendKeepAlive(bChannelAcquisition = false) {
    isDormant = false;
    const packet = createKeepAlivePacket(bChannelAcquisition);
    console.log(`Client -> Server: Sending Keep Alive packet (${packet.length} bytes)`);
    sendPacket(packet);
}
/**
 * Create Keep Alive packet
 */
function createKeepAlivePacket(bChannelAcquisition) {
    const header = createHeader(7); // 7 is ecKeepAlive
    // Add any additional Keep Alive data based on your protocol
    return header;
}
/**
 * Send initial Register packet
 */
function sendRegisterPacket() {
    const header = createHeader(COMMAND_REGISTER);
    console.log(`Client -> Server: Sending Register packet (${header.length} bytes)`);
    sendPacket(header);
    sequenceMinor++;
}
/**
 * Handle Register response
 */
function handleRegisterResponse() {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            client.removeListener('message', onMessage);
            reject(new Error('Timeout waiting for Register response'));
        }, 5000); // 5 seconds timeout
        function onMessage(msg, rinfo) {
            clearTimeout(timeout);
            client.removeListener('message', onMessage);
            console.log(`Received response from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
            handlePacket(msg);
            resolve();
        }
        client.on('message', onMessage);
    });
}
/**
 * Initialize the client
 */
function initializeClient() {
    client.on('message', (msg, rinfo) => {
        console.log(`Received message from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
        handlePacket(msg);
    });
    client.on('error', (err) => {
        console.error('UDP error:', err);
        client.close();
    });
}
/**
 * Main function to run the client
 */
function runClient() {
    return __awaiter(this, void 0, void 0, function* () {
        initializeClient();
        try {
            console.log('Sending initial Register packet...');
            sendRegisterPacket();
            console.log('Waiting for Register response...');
            yield handleRegisterResponse();
            console.log('Starting Keep Alive loop...');
            setInterval(() => {
                sendKeepAlive();
            }, 7000); // Send Keep Alive every 7 seconds
        }
        catch (error) {
            console.error('Error in client operation:', error);
        }
    });
}
// Run the client
runClient();
