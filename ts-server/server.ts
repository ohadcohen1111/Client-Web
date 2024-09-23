import dgram, { RemoteInfo } from 'dgram';
import { ECommand, createFieldReader, getCommandString } from './utils';
import { logger } from './logger';
import { PacketHeader } from './packets/PacketHeader';
import { PacketRegister } from './packets/PacketRegister';
import { PacketAuthorize } from './packets/PacketAuthorize';
import { Packet } from './packets/Packet';

// Type definitions
type Server = { ip: string; port: number; id: number | null };

// Constants
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;

// Variables
let previousCommand = ECommand.ecRegister;
let isRegistered = false;
let authState: 'UNAUTHORIZED' | 'AUTHORIZED' = 'UNAUTHORIZED';
let currentServerID = 0;
let lastSenderId: bigint = 0n;
let server: Server = { ip: SERVER_IP, port: SERVER_PORT, id: null };

const client = dgram.createSocket('udp4');

// Utility Functions

function handlePacket(msg: Buffer) {
    const header = PacketHeader.fromBuffer(msg);
    logger.debug(`Received packet: Command ${getCommandString(header.command)} (${msg.length} bytes)`);
    lastSenderId = msg.readBigUInt64BE(12);
    printRecievedPacket(msg, "received");

    // Update server ID if it's not set
    if (server.id === null) {
        server.id = msg.readUInt8(20);
    }

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Rx: ${server.id}.${header.sequenceMajor > 0 ? 'R' : 'L'}${header.sequenceMajor}.${header.sequenceMinor}, (${previousCommand}):(${header.command}) ${getCommandString(header.command)}  ${server.ip}:${server.port}`);
    //previousCommand = header.command;

    // Handle different packet types
    switch (header.command) {
        case ECommand.ecAuthorize:
            handleAuthorizePacket(msg, previousCommand);
            break;
        case ECommand.ecAck:
            handleAckPacket(msg.slice(23));
            break;
    }
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
        //sendRegisterPacket();
        const registerPacket = new PacketRegister();
        sendPacket(registerPacket);
    }
}

function handleAuthorizePacket(packet: Buffer, previousCommand: ECommand) {
    const header = PacketHeader.fromBuffer(packet.slice(0, 23)); // Assuming header is 23 bytes
    const authorizePacket = new PacketAuthorize(previousCommand, header, packet.slice(23));
    authorizePacket.parseData();
    console.log('Received Authorize Packet:', authorizePacket);
    sendPacket(authorizePacket);
}

function sendPacket(packet: Packet) {
    previousCommand = packet.header.command;
    const buffer = packet.toBuffer();
    logger.debug(`Send packet:(${buffer.length} bytes)`);

    printSentPacket(packet, "sent");

    // Log the sent packet
    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Tx: ${packet.header.sequenceMajor > 0 ? 'R' : 'L'}${packet.header.sequenceMajor}.${packet.header.sequenceMinor}, (00):(${packet.header.command}) ${getCommandString(packet.header.command)}, ${SERVER_IP}:${SERVER_PORT}`);

    client.send(buffer, SERVER_PORT, SERVER_IP, (err) => {
        if (err) {
            logger.error('Error sending packet:', err);
        } else {
            logger.info(`Packet sent to ${SERVER_IP}:${SERVER_PORT}`);
        }
    });
}

function printRecievedPacket(packet: Buffer, senderOrReceiver: string) {
    const bitString = Array.from(packet)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join(' ');

    console.log('=============');
    console.log(`The packet that was ${senderOrReceiver} (bits):`);
    console.log(bitString);
    console.log('=============');
}

function printSentPacket(packet: Packet, senderOrReceiver: string) {
    const bitString = Array.from(packet.toBuffer())
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join(' ');

    console.log('=============');
    console.log(`The packet that was ${senderOrReceiver} (bits):`);
    console.log(bitString);
    console.log('=============');
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
        const registerPacket = new PacketRegister();
        sendPacket(registerPacket);
    } catch (error) {
        logger.error('Error in client operation:', error);
    }
}

runClient();