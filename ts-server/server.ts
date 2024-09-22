import dgram, { RemoteInfo } from 'dgram';
import { toBufferBE } from 'bigint-buffer';
import { base64Encode, calcResponse } from './cryptoUtils';
import { getSIPMethod, writeBits as writeBitsUtil, ECommand, getCurrentTimeMs, readBits, readString, createFieldReader, getCommandString } from './utils';
import { logger } from './logger';
import { PacketHeader, parseHeader } from './packets/PacketHeader';

// Type definitions
type PacketState = { offset: number; bitOffset: number };
type Server = { ip: string; port: number; id: number | null };
type CPacketAuthorize = {
    ALGORITHM: number;
    AUTH_METHOD: number;
    URI: string;
    RFU1: number;
    REALM: string;
    NONCE: number;
    OPAQUE: number;
    METHOD: string;
    RESPONSE: string;
    USERNAME: string;
    EAUTH_DEVICE_ID: bigint;
    EAUTH_PASS_TYPE: number;
};

// Constants
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;
const MAX_SEQ_MAJOR = 255;
const MAX_SEQ_MINOR = 255;

// Variables
let DEVICE_ID: bigint = 0n;
let sequenceMajor: number = 0;
let sequenceMinor: number = 0;
let previousCommand = ECommand.ecRegister;
let isRegistered = false;
let authState: 'UNAUTHORIZED' | 'AUTHORIZED' = 'UNAUTHORIZED';
let currentServerID = 0;
let lastSenderId: bigint = 0n;
let server: Server = { ip: SERVER_IP, port: SERVER_PORT, id: null };

const client = dgram.createSocket('udp4');

// Utility Functions

function incrementSequence() {
    sequenceMinor++;
    if (sequenceMinor > MAX_SEQ_MINOR) {
        sequenceMinor = 0;
        sequenceMajor = (sequenceMajor + 1) % (MAX_SEQ_MAJOR + 1);
    }
}

function resetSequence(seqMajor: number) {
    sequenceMajor = seqMajor + 1;
    sequenceMinor = 0;
}

function createHeader(command: number): Buffer {
    const header = Buffer.alloc(23);
    header.writeUInt32BE(0x0200001C, 0);
    toBufferBE(BigInt(lastSenderId), 8).copy(header, 4);
    toBufferBE(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12);
    header.writeUInt8(sequenceMajor, 20);
    header.writeUInt8(sequenceMinor, 21);

    const commandByte = (command << 2) | 0x1;
    header.writeUInt8(commandByte, 22);
    return header;
}

function createCPacketAuthorize(
    algorithm: number, authMethod: number, uri: string, realm: string, nonce: number, opaque: number,
    method: string, response: string, username: string, deviceId1: bigint, passType: number
): Buffer {
    const buffer = Buffer.alloc(239);
    let offset = 0;
    let bitOffset = 0;

    function writeBits(value: number | bigint, bits: number) {
        while (bits > 0) {
            const availableBits = 8 - (bitOffset % 8);
            const bitsToWrite = Math.min(availableBits, bits);
            const mask = (1 << bitsToWrite) - 1;
            const shiftedValue = (Number(value) & mask) << (availableBits - bitsToWrite);
            buffer[offset] |= shiftedValue;
            value = Number(value) >> bitsToWrite;
            bits -= bitsToWrite;
            bitOffset += bitsToWrite;
            if (bitOffset % 8 === 0) {
                offset++;
            }
        }
    }

    function writeString(str: string, maxBytes: number) {
        const buf = Buffer.from(str, 'utf8');
        buf.copy(buffer, offset, 0, Math.min(buf.length, maxBytes));
        offset += maxBytes;
        bitOffset = offset * 8;
    }

    writeBits(algorithm, 4);
    writeBits(authMethod, 4);
    writeString(uri, 63);
    writeBits(0, 8);
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

    buffer.writeBigUInt64BE(DEVICE_ID, offset);

    return buffer;
}


function parseCPacketAuthorize(buffer: Buffer, prevCommand: ECommand) {
    let bitOffset = 0;
    const parsedPacket: CPacketAuthorize = {
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
        EAUTH_DEVICE_ID: BigInt(readBits(buffer, bitOffset += 504, 64)),
        EAUTH_PASS_TYPE: readBits(buffer, bitOffset += 64, 4)
    };

    const nonceBuffer = Buffer.alloc(4);
    nonceBuffer.writeUInt32BE(parsedPacket.NONCE);
    const base64Nonce = base64Encode(nonceBuffer);

    const username = "999000000000075087";
    const password = "12345";
    const method = getSIPMethod(prevCommand || 0);

    const response = calcResponse(
        username,
        parsedPacket.REALM,
        password,
        method,
        parsedPacket.URI,
        base64Nonce
    );

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
        DEVICE_ID,
        parsedPacket.EAUTH_PASS_TYPE
    );

    const header = createHeader(ECommand.ecAuthorize);
    const fullPacket = Buffer.concat([header, packetBody]);

    sendPacket(fullPacket, ECommand.ecAuthorize);
}

function createRegisterPacketBody(): Buffer {
    DEVICE_ID = getCurrentTimeMs();
    const body = Buffer.alloc(57);
    let state: PacketState = { offset: 0, bitOffset: 0 };

    writeBitsUtil(body, 33882126, 32, state);
    writeBitsUtil(body, 1208025285, 32, state);
    writeBitsUtil(body, 6, 32, state);
    writeBitsUtil(body, 587989143, 32, state);
    writeBitsUtil(body, 49537, 32, state);
    writeBitsUtil(body, 57457, 16, state);
    writeBitsUtil(body, 57458, 16, state);
    writeBitsUtil(body, 2, 8, state);
    writeBitsUtil(body, 0n, 64, state);
    writeBitsUtil(body, 0n, 64, state);
    writeBitsUtil(body, 0n, 64, state);
    writeBitsUtil(body, DEVICE_ID, 64, state);

    return body;
}

function handlePacket(msg: Buffer) {
    const header = parseHeader(msg);
    logger.debug(`Received packet: Command ${getCommandString(header.commandID)} (${msg.length} bytes)`);
    lastSenderId = msg.readBigUInt64BE(12);
    printPacket(msg, "received");

    // Update server ID if it's not set
    if (server.id === null) {
        server.id = msg.readUInt8(20);
    }

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Rx: ${server.id}.${sequenceMajor > 0 ? 'R' : 'L'}${sequenceMajor}.${header.sequenceMinor}, (${previousCommand}):(${header.commandID}) ${getCommandString(header.commandID)}  ${server.ip}:${server.port}`);
    incrementSequence();

    if (header.commandID === ECommand.ecAck) {
        resetSequence(header.sequenceMajor);
        const body = msg.slice(23);
        handleAckPacket(body);
    }
    else if (header.commandID === ECommand.ecAuthorize) {
        const body = msg.slice(23);
        handleAuthorizePacket(body);
    }
    previousCommand = header.commandID;
}

function handleAckPacket(packet: Buffer) {
    // Create a field reader for the packet buffer
    const readField = createFieldReader(packet);

    // Use readField to read fields with automatic offset management
    const lastArxSec = readField(64);   // Read 64-bit field
    const systemMode = readField(8);    // Read 8-bit field
    const serverID = readField(64);     // Read 64-bit field
    const additionalField = readField(32); // Read additional 32-bit field if needed

    logger.info('ACK Packet Contents:', {
        lastArxSec,
        systemMode,
        serverID
    });

    if (previousCommand === ECommand.ecRegister) {
        logger.info('Received ACK after registration');
        isRegistered = true;
    } else if (previousCommand === ECommand.ecAuthorize) {
        logger.info('Received ACK after authorization');
        authState = 'AUTHORIZED';
        sendRegisterPacket();
    }
}

function handleAuthorizePacket(packet: Buffer){
    parseCPacketAuthorize(packet, previousCommand);
}

function sendPacket(packet: Buffer, command: ECommand) {
    logger.debug(`Send packet:(${packet.length} bytes)`);
    printPacket(packet, "sent");

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Tx: ${server.id || 0}.${sequenceMajor > 0 ? 'R' : 'L'}${sequenceMajor}.${sequenceMinor}, (00):(${command}) ${getCommandString(command)}, ${server.ip}:${server.port}`);

    client.send(packet, server.port, server.ip, (err) => {
        if (err) {
            logger.error('Error sending packet:', err);
        } else {
            logger.info(`Packet sent to ${server.ip}:${server.port}`);
        }
    });

    incrementSequence();
}

function printPacket(packet: Buffer, senderOrReceiver: string) {
    const bitString = Array.from(packet)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join(' ');

    console.log('=============');
    console.log(`The packet that was ${senderOrReceiver} (bits):`);
    console.log(bitString);
    console.log('=============');
}

function sendKeepAlive(bChannelAcquisition: boolean = false) {
    const packet = createKeepAlivePacket(bChannelAcquisition);
    logger.debug(`Sending Keep Alive packet to ${server.ip}:${server.port} with ${packet.length} bytes`);
    sendPacket(packet, ECommand.ecKeepAlive);
}

function createKeepAlivePacket(bChannelAcquisition: boolean): Buffer {
    const header = createHeader(ECommand.ecKeepAlive);
    return header;
}

function sendRegisterPacket() {
    const header = createHeader(ECommand.ecRegister);
    const body = createRegisterPacketBody();
    const fullPacket = Buffer.concat([header, body]);
    logger.info('Sending Register Packet');
    sendPacket(fullPacket, ECommand.ecRegister);
}

function initializeClient() {
    client.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
        handlePacket(msg);
    });

    client.on('error', (err: Error) => {
        logger.error('UDP error:', err);
        client.close();
    });
}

async function runClient() {
    initializeClient();

    try {
        logger.info('Starting client and sending initial Register packet...');
        sendRegisterPacket();
    } catch (error) {
        logger.error('Error in client operation:', error);
    }
}

runClient();