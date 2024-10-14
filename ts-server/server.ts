import dgram, { Socket, RemoteInfo } from 'dgram';
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
import { PacketError } from './packets/PacketError';
import { PacketEnablePtt } from './packets/PacketEnablePtt';
import { PacketDisablePtt } from './packets/PacketDisablePtt';
import { PacketCreateAdHoc } from './packets/PacketCreateAdHoc';
import { PacketAudio } from './packets/PacketAudio';

// Constants
const SERVER_IP = '82.166.254.181';
const CONTROL_PORT = 25000;
const AUDIO_PORT = 25001;

// Type definitions
type Server = { ip: string; controlPort: number; audioPort: number; id: number | null };

// Variables
let previousCommand = ECommand.ecRegister;
let isRegistered = false;
let authState: 'UNAUTHORIZED' | 'AUTHORIZED' = 'UNAUTHORIZED';
let currentServerID = 0;
let sessionId: bigint = 0n;
let lastSenderId: bigint = 0n;
let server: Server = { ip: SERVER_IP, controlPort: CONTROL_PORT, audioPort: AUDIO_PORT, id: null };
let keepAliveInterval: number = 0;
let frequentKeepAliveInterval: number = 0;
let keepAliveTimer: NodeJS.Timeout | null = null;

// Create two separate UDP sockets
const controlClient = dgram.createSocket('udp4');
const audioClient = dgram.createSocket('udp4');

// Utility Functions

function handleControlPacket(msg: Buffer) {
    const { header, data } = PacketParser.parsePacket(msg);
    logger.debug(`Received control packet: Command ${getCommandString(header.command)} (${msg.length} bytes)`);
    lastSenderId = msg.readBigUInt64BE(12);
    printPacket(msg, "received");

    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Rx: ${server.id}.${header.sequenceMajor > 0 ? 'R' : 'L'}${header.sequenceMajor}.${header.sequenceMinor}, (${previousCommand}):(${header.command}) ${getCommandString(header.command)}  ${server.ip}:${server.controlPort}`);

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
        case ECommand.ecError:
            handleError(header, data);
            break;
        case ECommand.ecEnablePTT:
            handleEnablePtt(header, data);
            break;
        case ECommand.ecDisablePTT:
            handleDisablePtt(header, data);
            break;
        case ECommand.ecKeepAlive:
            handleKeepAlive(header, data)
            break;
        default:
            logger.warn(`Unhandled control packet type: ${getCommandString(header.command)}`);
    }
}

function handleAudioPacket(msg: Buffer) {
    logger.debug(`Received audio packet: (${msg.length} bytes)`);
    // Implement audio packet handling logic here
    // This might include decoding the audio data, playing it, or processing it in some way

    const packet = new PacketAudio(msg);
    console.log(packet.toString());
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
        sendControlPacket(registerPacket);
    }
    else if (previousCommand === ECommand.ecPending) {
        const packetAccept = new PacketAccept(header, data, true, sessionId);
        packetAccept.header.sequenceMajor = 3;
        packetAccept.header.sequenceMinor = 0;
        sendControlPacket(packetAccept);

        // const emptyBuffer = Buffer.alloc(0);  // Create an empty buffer
        // sendAudioPacket(emptyBuffer);

        // Create the specific binary buffer
        const specificBuffer = createSpecificBuffer();
        sendAudioPacket(specificBuffer);

        //const packetAudio = new PacketAudio();
    }
}

function createSpecificBuffer(): Buffer {
    const binaryString = '00000010 00000000 00000000 00011100 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111 00001101 11011101 00101001 00110101 00000010 10011110 10100101 01001111 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000';

    // Remove spaces and convert to byte array
    const bytes = binaryString.replace(/\s/g, '').match(/.{8}/g)!.map(byte => parseInt(byte, 2));

    return Buffer.from(bytes);
}

function handleApprovedPacket(header: PacketHeader, data: Buffer) {
    const approvedPacket = new PacketApproved(header, data, false);
    approvedPacket.parseData();

    keepAliveInterval = approvedPacket.parsedPacket.keepAlive;
    frequentKeepAliveInterval = approvedPacket.parsedPacket.freqKeepAlive;

    // logger.info(`Initialized KeepAlive intervals: normal=${keepAliveInterval} seconds, frequent=${frequentKeepAliveInterval} seconds`);


    // // Start the KeepAlive timer
    startKeepAliveTimer();

    const pabSyncRequestPacket = new PacketPabSyncRequest();
    sendControlPacket(pabSyncRequestPacket)
}

// Add these new functions
function startKeepAliveTimer() {
    // Clear any existing timer
    if (keepAliveTimer) {
        clearInterval(keepAliveTimer);
    }

    // Start a new timer
    keepAliveTimer = setInterval(() => {
        sendKeepAlivePacket();
    }, frequentKeepAliveInterval * 1000); // Convert seconds to milliseconds

    logger.info(`KeepAlive timer started. Interval: ${keepAliveInterval} seconds`);
}

function sendKeepAlivePacket() {
    logger.debug('Sending KeepAlive packet');
    const keepAlivePacket = new PacketKeepAlive();
    keepAlivePacket.header.sequenceMajor = 2;
    keepAlivePacket.header.sequenceMinor = 0;
    sendControlPacket(keepAlivePacket);
}

function handlePabGroupListEx(header: PacketHeader, data: Buffer) {
    const packetPabGroupListEx = new PacketPabGroupListEx(header, data, false);
    packetPabGroupListEx.parseData();
    packetPabGroupListEx.printGroups();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);
}

function handlePabContactList(header: PacketHeader, data: Buffer) {
    const packetPabContactList = new PacketPabContactList(header, data, false);
    packetPabContactList.parseData();
    packetPabContactList.printContacts();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);
}

function handlePabGroupIdList(header: PacketHeader, data: Buffer) {
    const packetPabGroupIdList = new PacketPabGroupIdList(header, data, false);
    packetPabGroupIdList.parseData();
    packetPabGroupIdList.printInfo();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);
}

function handlePabSyncRequest(header: PacketHeader, data: Buffer) {
    const packetPabSyncRequest = new PacketPabSyncRequest(header, data, false);
    packetPabSyncRequest.parseData();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);

    const packetKeepAlive = new PacketKeepAlive();
}

function handlePacketPabStateList(header: PacketHeader, data: Buffer) {
    const packetPabStateList = new PacketPabStateList(header, data, false);
    packetPabStateList.parseData();
    packetPabStateList.printInfo();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);
}

function handlePacketPabSessionUpdatesList(header: PacketHeader, data: Buffer) {
    const packetPabSessionUpdatesList = new PacketPabSessionUpdatesList(header, data, false);
    packetPabSessionUpdatesList.parseData();

    const packetAck = new PacketAck(header);
    sendControlPacket(packetAck);
}

function handleNewSession(header: PacketHeader, data: Buffer) {
    const packetNewSession = new PacketNewSession(header, data, false);
    packetNewSession.parseData();
    packetNewSession.printInfo();
    sessionId = packetNewSession.sessionId;
    const packetPending = new PacketPending(header, data, true, sessionId);
    sendControlPacket(packetPending);
}

function handlePending(header: PacketHeader, data: Buffer) {
    logger.info('Pending packet received, no implementation yet');
}

function handleError(header: PacketHeader, data: Buffer) {
    const packetError = new PacketError(header, data, false);
    packetError.parseData();
    packetError.printInfo();
}

function handleEnablePtt(header: PacketHeader, data: Buffer) {
    const packetEnablePtt = new PacketEnablePtt(header, data, false);
    packetEnablePtt.parseData();
    packetEnablePtt.printInfo();

    const packetAck = new PacketAck(header, data);
    sendControlPacket(packetAck);
}

function handleDisablePtt(header: PacketHeader, data: Buffer) {
    const packetDisablePtt = new PacketDisablePtt(header, data, false);
    packetDisablePtt.parseData();
    packetDisablePtt.printInfo();

    const packetAck = new PacketAck(header, data);
    sendControlPacket(packetAck);
    // const emptyBuffer = Buffer.alloc(0);  // Create an empty buffer
    // sendAudioPacket(emptyBuffer);

    // const packetCreateAdHoc = new PacketCreateAdHoc(header);
    // sendControlPacket(packetCreateAdHoc);
}

function handleKeepAlive(header: PacketHeader, data: Buffer) {
    const packetAck = new PacketAck(header, data);
    sendControlPacket(packetAck);
}

function handleAuthorizePacket(header: PacketHeader, body: Buffer, previousCommand: ECommand) {
    const authorizePacket = new PacketAuthorize(previousCommand, header, body);
    authorizePacket.parseData();
    console.log('Received Authorize Packet:', authorizePacket);
    sendControlPacket(authorizePacket);
}

function sendControlPacket(packet: Packet) {
    previousCommand = packet.header.command;
    const buffer = packet.toBuffer();
    //logger.debug(`Sending control packet: (${buffer.length} bytes)`);

    // Restore the original logging format
    logger.debug(`  Med M: CtlProtocol.  00074  ${new Date().toLocaleString()}    Tx: ${packet.header.sequenceMajor > 0 ? 'R' : 'L'}${packet.header.sequenceMajor}.${packet.header.sequenceMinor}, (00):(${packet.header.command}) ${getCommandString(packet.header.command)}, ${SERVER_IP}:${server.controlPort}`);

    sendUDPPacket(controlClient, buffer, server.controlPort, 'control');
}

function sendAudioPacket(audioData: Buffer) {
    sendUDPPacket(audioClient, audioData, server.audioPort, 'audio');
}

function sendUDPPacket(client: Socket, data: Buffer, port: number, type: 'control' | 'audio') {
    logger.debug(`Sending ${type} packet: (${data.length} bytes)`);

    client.send(data, port, SERVER_IP, (err) => {
        if (err) {
            logger.error(`Error sending ${type} packet:`, err);
        } else {
            logger.info(`${type.charAt(0).toUpperCase() + type.slice(1)} packet sent to ${SERVER_IP}:${port}`);
        }
    });
}

function initializeClients() {
    controlClient.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
        handleControlPacket(msg);
    });

    audioClient.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
        handleAudioPacket(msg);
    });

    controlClient.on('error', (err: Error) => {
        logger.error('Control UDP error:', err);
        controlClient.close();
    });

    audioClient.on('error', (err: Error) => {
        logger.error('Audio UDP error:', err);
        audioClient.close();
    });
}

async function runClient() {
    initializeClients();

    try {
        logger.info('Starting client and sending initial Register packet...');
        const registerPacket = new PacketRegister();
        sendControlPacket(registerPacket);

        // Example of how you might send an audio packet
        // Note: You'll need to implement the actual audio data generation
        // setInterval(() => {
        //     const audioData = generateAudioData(); // Implement this function
        //     sendAudioPacket(audioData);
        // }, 20); // Send audio packet every 20ms (adjust as needed)
    } catch (error) {
        logger.error('Error in client operation:', error);
    }
}

runClient();