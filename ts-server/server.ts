import dgram, { RemoteInfo } from 'dgram';
import { ECommand, createFieldReader, getCommandString, printPacket } from './utils';
import { logger } from './logger';
import { PacketHeader } from './packets/PacketHeader';
import { PacketRegister } from './packets/PacketRegister';
import { PacketAuthorize } from './packets/PacketAuthorize';
import { Packet } from './packets/Packet';
import { PacketApproved } from './packets/PacketApproved';
import { PacketKeepAlive } from './packets/PacketKeepAlive';
import { PacketAck } from './packets/PacketAck';
import { PacketPabSyncRequest } from './packets/PacketPabSyncRequest';
import { PacketParser } from './packets/PacketParser';
import { PacketPabGroupListEx } from './packets/PacketPabGroupListEx';

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

let keepAliveInterval: number = 0;
let frequentKeepAliveInterval: number = 0;

const client = dgram.createSocket('udp4');

// Utility Functions

function handlePacket(msg: Buffer) {
    const { header, data } = PacketParser.parsePacket(msg);
    if (header.command != ECommand.ecAuthorize && header.command != ECommand.ecAck &&
        header.command != ECommand.ecApproved) {
        console.log(header.command);
    }
    logger.debug(`Received packet: Command ${getCommandString(header.command)} (${msg.length} bytes)`);
    lastSenderId = msg.readBigUInt64BE(12);
    printPacket(msg, "received");

    // Update server ID if it's not set
    if (server.id === null) {
        server.id = msg.readUInt8(20);
    }

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Rx: ${server.id}.${header.sequenceMajor > 0 ? 'R' : 'L'}${header.sequenceMajor}.${header.sequenceMinor}, (${previousCommand}):(${header.command}) ${getCommandString(header.command)}  ${server.ip}:${server.port}`);
    //previousCommand = header.command;

    // Handle different packet types
    switch (header.command) {
        case ECommand.ecAuthorize:
            handleAuthorizePacket(header, data, previousCommand);
            break;
        case ECommand.ecAck:
            handleAckPacket(data);
            break;
        case ECommand.ecApproved:
            handleApprovedPacket(header, data);
            break;
        case ECommand.ecPABGroupListEx:
            handlePabGroupListEx(header, data);
        // case ECommand.ecPABGroupList:
        //     handlePabGroupList(data);
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

function handleApprovedPacket(header: PacketHeader, data: Buffer) {
    const approvedPacket = new PacketApproved(header, data, false);
    approvedPacket.parseData();

    // Initialize keep-alive intervals
    keepAliveInterval = approvedPacket.parsedPacket.keepAlive;
    frequentKeepAliveInterval = approvedPacket.parsedPacket.freqKeepAlive;

    logger.info(`Initialized KeepAlive intervals: normal=${keepAliveInterval} seconds, frequent=${frequentKeepAliveInterval} seconds`);

    // Create and send PabSyncRequest packet
    const pabSyncRequestPacket = new PacketPabSyncRequest();
    sendPacket(pabSyncRequestPacket)
}

function handlePabGroupListEx(header: PacketHeader, data: Buffer) {
    const packetPabGroupListEx = new PacketPabGroupListEx(header, data, false);
    packetPabGroupListEx.parseData();
    packetPabGroupListEx.printGroups();
}


function handleAuthorizePacket(header: PacketHeader, body: Buffer, previousCommand: ECommand) {
    const authorizePacket = new PacketAuthorize(previousCommand, header, body);
    authorizePacket.parseData();
    console.log('Received Authorize Packet:', authorizePacket);
    sendPacket(authorizePacket);
}

function sendPacket(packet: Packet) {
    previousCommand = packet.header.command;
    const buffer = packet.toBuffer();
    logger.debug(`Send packet:(${buffer.length} bytes)`);

    printPacket(packet, "sent");

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