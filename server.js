import dgram from 'dgram';  // Import dgram as an ES6 module
import { toBufferBE } from 'bigint-buffer';  // Import the function from bigint-buffer
import { base64Encode, calcResponse } from './cryptoUtils.js';  // Import your own module
import { getSIPMethod, writeBits } from './utils.js';
import os from 'os';

const client = dgram.createSocket('udp4');

// Server details
//const SERVER_IP = '82.166.254.181';
//const SERVER_IP = '192.168.50.149';
const SERVER_IP = '192.168.1.207';
const SERVER_PORT = 25000;

// Command for ecAuthorize
const COMMAND_AUTHORIZE = 38;
const COMMAND_REGISTER = 5;
const COMMAND_ACK = 1;
let DEVICE_ID = 0;

let previousCommand = 5; // Assuming the initial command is ecRegister (5)
let sequenceMinor = 0;

// Add these variables at the top of your file
let isRegistered = false;
let authState = 'UNAUTHORIZED';
let currentServerID = 0;

// New variable to store the senderId
let lastSenderId = 0;

// Server management
let server = { ip: SERVER_IP, port: SERVER_PORT, id: null };

// Function to get current time in milliseconds (equivalent to iprs_get_time_ms)
function getCurrentTimeMs() {
    const uptimeMs = Math.floor(os.uptime() * 1000); // Get system uptime in milliseconds
    return BigInt(uptimeMs);
}

/**
 * Helper function to read a specific number of bits
 * @param {Buffer} buffer - Source buffer
 * @param {number} bitOffset - Starting bit offset
 * @param {number} numBits - Number of bits to read
 * @returns {number} Read value
 */
function readBits(buffer, bitOffset, numBits) {
    const binaryString = buffer.toString('binary').split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    const value = parseInt(binaryString.substr(bitOffset, numBits), 2);
    return value;
}

/**
 * Helper function to read a string of bits
 * @param {Buffer} buffer - Source buffer
 * @param {number} bitOffset - Starting bit offset
 * @param {number} numBits - Number of bits to read
 * @returns {string} Read string
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
 * Create header for packets
 * @param {number} command - Command number
 * @returns {Buffer} Header buffer
 */
function createHeader(command, seqMinor = sequenceMinor, seqMajor = 0) {
    const header = Buffer.alloc(23);
    header.writeUInt32BE(0x0200001C, 0);  // Protocol Version
    toBufferBE(BigInt(lastSenderId), 8).copy(header, 4);  // Recipient ID
    toBufferBE(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12);  // Sender ID
    header.writeUInt8(seqMajor, 20);  // Sequence (major)
    header.writeUInt8(seqMinor, 21);  // Sequence (minor)

    // Modify the last byte to set the unused bit to 1
    const commandByte = (command << 2) | 0x1;  // Set the last bit to 1
    header.writeUInt8(commandByte, 22);  // Command + Flags + Unused bit

    return header;
}

/**
 * Create CPacketAuthorize packet
 * @param {number} algorithm - Algorithm
 * @param {number} authMethod - Authentication method
 * @param {string} uri - URI
 * @param {string} realm - Realm
 * @param {number} nonce - Nonce
 * @param {number} opaque - Opaque
 * @param {string} method - Method
 * @param {string} response - Response
 * @param {string} username - Username
 * @param {number} deviceId - Device ID
 * @param {number} passType - Password type
 * @returns {Buffer} CPacketAuthorize buffer
 */
function createCPacketAuthorize(algorithm, authMethod, uri, realm, nonce, opaque, method, response, username, deviceId1, passType) {
    const buffer = Buffer.alloc(239);
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
    writeBits(0, 8);  // RFU1
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

    //const deviceId = getCurrentTimeMs();
    buffer.writeBigUInt64BE(DEVICE_ID, offset);
    // offset += 8;
    // bitOffset = offset * 8;
    // writeBits(passType, 4);

    return buffer;
}

/**
 * Parse CPacketAuthorize packet
 * @param {Buffer} buffer - Packet buffer
 * @param {number} prevCommand - Previous command
 * @returns {Object} Parsed packet
 */
function parseCPacketAuthorize(buffer, prevCommand) {
    //console.log(`Server -> Client: Received CPacketAuthorize (${buffer.length} bytes)`);

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
        } else if (typeof value === 'number') {
            console.log(`${key}: ${value} (${value.toString(16)}h)`);
        } else {
            console.log(`${key}: ${value}`);
        }
    }

    // Set username and password for response calculation
    const username = "999000000000075087";
    const password = "12345";
    const method = getSIPMethod(prevCommand || 0);

    // Calculate the response
    const response = calcResponse(
        username,
        parsedPacket.REALM,
        password,
        method,
        parsedPacket.URI,
        base64Nonce
    );

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
        DEVICE_ID,  // Use the default or appropriate DeviceId
        parsedPacket.EAUTH_PASS_TYPE
    );

    sequenceMinor++;
    const header = createHeader(COMMAND_AUTHORIZE);
    const fullPacket = Buffer.concat([header, packetBody]);

    //console.log(`Client -> Server: Sending CPacketAuthorize (${fullPacket.length} bytes)`);
    sendPacket(fullPacket);

    return parsedPacket;
}

/**
 * Create Register packet body using bit-level precision
 * @returns {Buffer} Register packet body
 */
function createRegisterPacketBody() {
    DEVICE_ID = getCurrentTimeMs();

    const body = Buffer.alloc(57);  // Allocate enough space for the body
    let state = { offset: 0, bitOffset: 0 };

    // Writing values bit by bit using the imported writeBits function
    writeBits(body, 33882126, 32, state);  // CLIENT_PROTOCOL_VERSION (32 bits)
    writeBits(body, 1208025285, 32, state); // CLIENT_VERSION (32 bits)
    writeBits(body, 6, 32, state);          // CLIENT_TYPE (32 bits)
    writeBits(body, 587989143, 32, state);  // APP_VERSION (32 bits)
    writeBits(body, 49537, 32, state);      // VOCODER_AND_SERVICES_MASK (32 bits)
    writeBits(body, 57457, 16, state);      // CONTROL_PORT (16 bits)
    writeBits(body, 57458, 16, state);      // AUDIO_PORT (16 bits)
    writeBits(body, 2, 8, state);           // INITIAL_STATE (8 bits)
    writeBits(body, 0n, 64, state);         // DIRECTORY_NUMBER (64 bits, BigInt)
    writeBits(body, 0n, 64, state);         // MOBILE_SUBSCRIBER_ID (64 bits, BigInt)
    writeBits(body, 0n, 64, state);         // MOBILE_EQUIPMENT_ID (64 bits, BigInt)
    writeBits(body, DEVICE_ID, 64, state);  // DEVICE_ID (64 bits, BigInt)

    return body;
}

/**
 * Handle incoming packets
 * @param {Buffer} msg - Received message buffer
 */
function handlePacket(msg) {
    //console.log(`Received packet: Command ${(msg.readUInt8(22) >> 2) & 0x3F} (${msg.length} bytes)`);

    // Extract the senderId from the header (assume it starts at offset 12)
    lastSenderId = msg.readBigUInt64BE(12);  // Adjust this offset as needed
    console.log(`Extracted senderId: ${lastSenderId.toString(16)}`);

    // Print the received packet in bit format
    printPacket(msg, "recieved");
    const command = (msg.readUInt8(22) >> 2) & 0x3F;
    console.log(`Received packet: Command ${command} (${msg.length} bytes)`);

    if (command === COMMAND_AUTHORIZE) {
        console.log('Received ecAuthorize packet');
        const body = msg.slice(23);  // The body starts after the 23-byte header
        parseCPacketAuthorize(body, previousCommand);
    } else if (command === COMMAND_ACK) {
        console.log('Received ACK packet');
        const body = msg.slice(23);  // The body starts after the 23-byte header
        handleAckPacket(body);
    } else {
        console.log(`Received command: ${command}`);
        previousCommand = command;  // Update the previous command
    }

    previousCommand = command;
}

/**
 * Handle ACK packet
 * @param {Buffer} packet - ACK packet buffer
 */
function handleAckPacket(packet) {
    console.log('Parsing ACK packet');

    let offset = 0; // Start at the beginning of the packet body

    // Parse ACK packet fields
    const lastArxSec = readBits(packet, offset, 64); // 8 bytes (64 bits) for LAST_ARX_SEC
    offset += 64;

    const systemMode = readBits(packet, offset, 8); // 1 byte (8 bits) for SYSTEM_MODE
    offset += 8;

    const serverID = readBits(packet, offset, 64); // 8 bytes (64 bits) for Server ID

    console.log('ACK Packet Contents:');
    console.log(`LAST_ARX_SEC: ${lastArxSec}`);
    console.log(`SYSTEM_MODE: ${systemMode}`);
    console.log(`Server ID: ${serverID}`);

    // Handle based on previous command
    if (previousCommand === COMMAND_REGISTER) {
        console.log('Received ACK after registration');
        isRegistered = true;
    } else if (previousCommand === COMMAND_AUTHORIZE) {
        console.log('Received ACK after authorization');
        authState = 'AUTHORIZED';
        sendRegisterPacket(0, 1);
    }

    // Update server ID if needed
    // if (serverID !== 0n && serverID !== BigInt(currentServerID)) {
    //     console.log(`Server ID changed from ${currentServerID} to ${serverID}`);
    //     currentServerID = Number(serverID);
    // }

    // Implement any other necessary state changes or actions based on the ACK
    //updateClientState();
}

// Helper function to update client state
function updateClientState() {
    if (isRegistered && authState === 'AUTHORIZED') {
        console.log('Client fully registered and authorized');
        // Implement any necessary actions for a fully operational state
    }
}

/**
 * Send a packet to the server
 * @param {Buffer} packet - Packet to send
 */
function sendPacket(packet) {
    console.log(`Client -> Server: (${packet.length} bytes)`);
    printPacket(packet, "sent");  // Call printPacket before sending the packet

    client.send(packet, server.port, server.ip, (err) => {
        if (err) {
            console.error('Error sending packet:', err);
        } else {
            console.log(`Packet sent to ${server.ip}:${server.port}`);
        }
    });
}

/**
 * Convert a buffer to a bit string in a nicely formatted way
 * @param {Buffer} packet - The packet buffer to be converted to bits
 */
function printPacket(packet, senderOrReceiver) {
    // Convert the packet to a binary string and format it into groups of 8 bits
    const bitString = Array.from(packet)
        .map(byte => byte.toString(2).padStart(8, '0'))  // Convert each byte to binary (8 bits) and pad with zeros
        .join(' ')  // Join the bytes into a single string with space-separated groups of 8 bits

    // Print the formatted output
    console.log('=============');
    console.log(`The packet that was ${senderOrReceiver} (bits):`);
    console.log(bitString);
    console.log('=============');
}

/**
 * Send Keep Alive packet
 * @param {boolean} bChannelAcquisition - Channel acquisition flag
 */
function sendKeepAlive(bChannelAcquisition = false) {
    //isDormant = false;

    const packet = createKeepAlivePacket(bChannelAcquisition);
    console.log(`Client -> Server: Sending Keep Alive packet (${packet.length} bytes)`);
    sendPacket(packet);
}

/**
 * Create Keep Alive packet
 * @param {boolean} bChannelAcquisition - Channel acquisition flag
 * @returns {Buffer} Keep Alive packet
 */
function createKeepAlivePacket(bChannelAcquisition) {
    const header = createHeader(4); // 4 is ecKeepAlive
    // You may need to add more data to the Keep Alive packet based on your protocol
    return header;
}

/**
 * Send initial Register packet
 */
function sendRegisterPacket(seqMinor = sequenceMinor, seqMajor = 0) {
    const header = createHeader(COMMAND_REGISTER, seqMinor, seqMajor);
    const body = createRegisterPacketBody();  // Create the body with the specified values
    const fullPacket = Buffer.concat([header, body]);
    //console.log(`Client -> Server: Sending Register packet (${fullPacket.length} bytes)`);
    sendPacket(fullPacket);
    sequenceMinor++;
}

/**
 * Handle Register response
 */
function handleRegisterResponse() {
    return new Promise((resolve, reject) => {
        // const timeout = setTimeout(() => {
        //     client.removeListener('message', onMessage);
        //     reject(new Error('Timeout waiting for Register response'));
        // }, 5000); // 5 seconds timeout

        function onMessage(msg, rinfo) {
            clearTimeout(timeout);
            client.removeListener('message', onMessage);

            //console.log(`Received response from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
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
        //console.log(`Received message from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
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
async function runClient() {
    initializeClient();

    try {
        console.log('Sending initial Register packet...');
        sendRegisterPacket();

        console.log('Waiting for Register response...');
        //await handleRegisterResponse();

        console.log('Starting Keep Alive loop...');
        // setInterval(() => {
        //     sendKeepAlive();
        // }, 7000); // Send Keep Alive every 30 seconds
    } catch (error) {
        console.error('Error in client operation:', error);
    }
}

// Run the client
runClient();