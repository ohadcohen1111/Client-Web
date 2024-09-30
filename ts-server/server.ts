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
import { PacketPabContactList } from './packets/PacketPabContactList';
import { PacketPabGroupIdList } from './packets/PacketPabGroupIdList';
import { PacketPabStateList } from './packets/PacketPabStateList';
import { PacketPabSessionUpdatesList } from './packets/PacketPabSessionUpdatesList';
import { PacketNewSession } from './packets/PacketNewSession';
import { PacketPending } from './packets/PacketPending';
import { PacketAccept } from './packets/PacketAccept';

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
    logger.debug(`Received packet: Command ${getCommandString(header.command)} (${msg.length} bytes)`);
    lastSenderId = msg.readBigUInt64BE(12);
    printPacket(msg, "received");

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Rx: ${server.id}.${header.sequenceMajor > 0 ? 'R' : 'L'}${header.sequenceMajor}.${header.sequenceMinor}, (${previousCommand}):(${header.command}) ${getCommandString(header.command)}  ${server.ip}:${server.port}`);
    //previousCommand = header.command;

    // Handle different packet types
    switch (header.command) {
        case ECommand.ecAuthorize:
            handleAuthorizePacket(header, data, previousCommand);
            break;
        case ECommand.ecAck:
            handleAckPacket(header, data);
            break;
        case ECommand.ecApproved:
            handleApprovedPacket(header, data);
            break;
        case ECommand.ecPABGroupListEx:
            handlePabGroupListEx(header, data);
            break;
        case ECommand.ecPABContactList:
            handlePabContactList(header, data);
            break;
        case ECommand.ecPABGroupIDList:
            handlePabGroupIdList(header, data);
            break;
        case ECommand.ecPABSyncRequest:
            handlePabSyncRequest(header, data);
            break;
        case ECommand.ecPABStateList:
            handlePacketPabStateList(header, data);
            break;
        case ECommand.ecPABSessionUpdatesList:
            handlePacketPabSessionUpdatesList(header, data);
            break;
        case ECommand.ecNewSession:
            handleNewSession(header, data);
            break;
        case ECommand.ecPending:
            handlePending(header, data);
            break;
        default:
    }
}

function handleAckPacket(header: PacketHeader, data: Buffer) {
    const packetAck = new PacketAck(header, data, false);
    packetAck.parseData();

    if (previousCommand === ECommand.ecRegister) {
        logger.info('Received ACK after registration');
        isRegistered = true;
    } else if (previousCommand === ECommand.ecAuthorize) {
        logger.info('Received ACK after authorization');
        authState = 'AUTHORIZED';
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

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handlePabContactList(header: PacketHeader, data: Buffer) {
    const packetPabContactList = new PacketPabContactList(header, data, false);
    packetPabContactList.parseData();
    packetPabContactList.printContacts();

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handlePabGroupIdList(header: PacketHeader, data: Buffer) {
    const packetPabGroupIdList = new PacketPabGroupIdList(header, data, false);
    packetPabGroupIdList.parseData();
    packetPabGroupIdList.printInfo();

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handlePabSyncRequest(header: PacketHeader, data: Buffer) {
    const packetPabSyncRequest = new PacketPabSyncRequest(header, data, false);
    packetPabSyncRequest.parseData();

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handlePacketPabStateList(header: PacketHeader, data: Buffer) {
    const packetPabStateList = new PacketPabStateList(header, data, false);
    packetPabStateList.parseData();
    packetPabStateList.printInfo();

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handlePacketPabSessionUpdatesList(header: PacketHeader, data: Buffer) {
    const packetPabSessionUpdatesList = new PacketPabSessionUpdatesList(header, data, false);
    packetPabSessionUpdatesList.parseData();

    const packetAck = new PacketAck(header);
    sendPacket(packetAck);
}

function handleNewSession(header: PacketHeader, data: Buffer) {
    const packetNewSession = new PacketNewSession(header, data, false);
    packetNewSession.parseData();
    packetNewSession.printInfo();

    const packetPending = new PacketPending(header, data, true, packetNewSession.sessionId);
    sendPacket(packetPending);
}

function handlePending(header: PacketHeader, data: Buffer) {
    console.log('Pending no implementation');
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