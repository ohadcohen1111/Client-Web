const dgram = require('dgram');
const { toBufferBE } = require('bigint-buffer');
const crypto = require('crypto');
const client = dgram.createSocket('udp4');

// Server details
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;

// Command for ecAuthorize
const COMMAND_AUTHORIZE = 38;

let previousCommand = 5; // Assuming the initial command is ecRegister (5)
let sequenceMinor = 0;

/**
 * Custom Base64 encoding function
 * @param {Buffer} srcBuffer - Source buffer to encode
 * @returns {string} Base64 encoded string
 */
function base64Encode(srcBuffer) {
    const cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const dest = [];
    let i = 0;
    while (i < srcBuffer.length) {
        const byte0 = srcBuffer[i];
        const byte1 = i + 1 < srcBuffer.length ? srcBuffer[i + 1] : 0;
        const byte2 = i + 2 < srcBuffer.length ? srcBuffer[i + 2] : 0;
        dest.push(
            cvt[byte0 & 0x3F],
            cvt[(byte0 >> 6) | ((byte1 & 0x0F) << 2)],
            i + 1 < srcBuffer.length ? cvt[(byte1 >> 4) | ((byte2 & 0x03) << 4)] : '=',
            i + 2 < srcBuffer.length ? cvt[byte2 >> 2] : '='
        );
        i += 3;
    }
    return dest.join('');
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
 * MD5 hash calculation helper function
 * @param {string} input - Input string to hash
 * @returns {string} MD5 hash
 */
function calcMD5(input) {
    return crypto.createHash('md5').update(input).digest('hex');
}

/**
 * Calculate the response for authorization
 * @param {string} username - Username
 * @param {string} realm - Realm
 * @param {string} password - Password
 * @param {string} method - SIP method
 * @param {string} uri - URI
 * @param {string} nonce - Nonce
 * @returns {string} Calculated response
 */
function calcResponse(username, realm, password, method, uri, nonce) {
    const ha1 = calcMD5(`${username}:${realm}:${password}`);
    const ha2 = calcMD5(`${method}:${uri}`);
    return calcMD5(`${ha1}:${nonce}:${ha2}`);
}

/**
 * Get SIP method based on command
 * @param {number} cmd - Command number
 * @returns {string} SIP method
 */
function GetSIPMethod(cmd) {
    switch (cmd) {
        case 1: // ecAck
        case 3: // ecAccept
        case 4: // ecReject
            return "ACK";
        case 38: // ecAuthorize
        case 39: // ecReRegister
            return "FORBIDDEN";
        case 5: // ecRegister
        case 6: // ecUnregister
        case 7: // ecKeepAlive
            return "REGISTER";
        case 7: // ecApproved
            return "APPROVED";
        case 8: // ecPocUriAction
        case 9: // ecCreateAdHoc
        case 10: // ecCreateAdHocEx
        case 11: // ecRedirectJoin
        case 12: // ecJoinEx
        case 13: // ecJoin
        case 14: // ecPending
        case 15: // ecNewSession
            return "INVITE";
        case 16: // ecLeave
        case 17: // ecEndSession
            return "BYE";
        case 21: // ecPABSyncRequest
        case 22: // ecSubscribe
            return "SUBSCRIBE";
        case 23: // ecEnablePTT
        case 24: // ecDisablePTT
        case 25: // ecControlPTT
        case 26: // ecForward
        case 27: // ecPABGroupList
        case 28: // ecPABContactList
        case 29: // ecPABGroupIDList
        case 30: // ecPABStateList
            return "NOTIFY";
        case 31: // ecPABSearch
        case 32: // ecPABSearchOrg
        case 33: // ecPABSearchResults
        case 34: // ecPABSearchOrgResults
        case 35: // ecPABSessionUpdatesList
        case 36: // ecDirSesLog
            return "INFO";
        default:
            return "ERROR";
    }
}

/**
 * Create header for packets
 * @param {number} command - Command number
 * @returns {Buffer} Header buffer
 */
function createHeader(command) {
    const header = Buffer.alloc(23);
    header.writeUInt32BE(0x0200001C, 0);  // Protocol Version
    toBufferBE(BigInt(0x0000000000000000), 8).copy(header, 4);  // Recipient ID
    toBufferBE(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12);  // Sender ID
    header.writeUInt8(0, 20);  // Sequence (major)
    header.writeUInt8(sequenceMinor, 21);  // Sequence (minor)
    header.writeUInt8((command << 2) | 0x0, 22);  // Command + Flags
    return header;
}

/**
 * Create header for packets
 * @param {number} command - Command number
 * @returns {Buffer} Header buffer
 */
function createHeader(command) {
    const header = Buffer.alloc(23);
    header.writeUInt32BE(0x0200001C, 0);  // Protocol Version
    toBufferBE(BigInt(0x0000000000000000), 8).copy(header, 4);  // Recipient ID
    toBufferBE(BigInt('0x0DDD2935029EA54F'), 8).copy(header, 12);  // Sender ID
    header.writeUInt8(0, 20);  // Sequence (major)
    header.writeUInt8(sequenceMinor, 21);  // Sequence (minor)
    header.writeUInt8((command << 2) | 0x0, 22);  // Command + Flags
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
    buffer.writeBigUInt64BE(BigInt(deviceId), offset);
    offset += 8;
    bitOffset = offset * 8;
    writeBits(passType, 4);

    return buffer;
}

/**
 * Parse CPacketAuthorize packet
 * @param {Buffer} buffer - Packet buffer
 * @param {number} prevCommand - Previous command
 * @returns {Object} Parsed packet
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
        } else if (typeof value === 'number') {
            console.log(`${key}: ${value} (${value.toString(16)}h)`);
        } else {
            console.log(`${key}: ${value}`);
        }
    }

    // Set username and password for response calculation
    const username = "999000000000075087";
    const password = "12345";
    const method = GetSIPMethod(prevCommand || 0);

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
        parsedPacket.EAUTH_DEVICE_ID,
        parsedPacket.EAUTH_PASS_TYPE
    );

    sequenceMinor++;
    const header = createHeader(COMMAND_AUTHORIZE);
    const fullPacket = Buffer.concat([header, packetBody]);

    console.log(`Client -> Server: Sending CPacketAuthorize (${fullPacket.length} bytes)`);
    client.send(fullPacket, SERVER_PORT, SERVER_IP, (err) => {
        if (err) {
            console.error('Error sending CPacketAuthorize:', err);
        } else {
            console.log('CPacketAuthorize sent successfully');
        }
    });

    return parsedPacket;
}

/**
 * Handle incoming packets
 * @param {Buffer} msg - Received message buffer
 */
function handlePacket(msg) {
    const command = (msg.readUInt8(22) >> 2) & 0x3F;
    console.log(`Received packet: Command ${command} (${msg.length} bytes)`);

    if (command === COMMAND_AUTHORIZE) {
        console.log('Received ecAuthorize packet');
        const body = msg.slice(23);  // The body starts after the 23-byte header
        parseCPacketAuthorize(body, previousCommand);
    } else {
        console.log(`Received command: ${command}`);
        previousCommand = command;  // Update the previous command
    }
}

// Listen for incoming UDP messages
client.on('message', (msg, rinfo) => {
    console.log(`Received message from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
    handlePacket(msg);
});

/**
 * Send initial Register packet
 */
function sendRegisterPacket() {
    const header = createHeader(5);  // 5 is ecRegister
    console.log(`Client -> Server: Sending Register packet (${header.length} bytes)`);
    client.send(header, SERVER_PORT, SERVER_IP, (err) => {
        if (err) {
            console.error('Error sending Register packet:', err);
        } else {
            console.log('Register packet sent successfully');
            sequenceMinor++;
        }
    });
}

// Send the initial Register packet
sendRegisterPacket();

// Handle any UDP errors
client.on('error', (err) => {
    console.error(`UDP error: ${err}`);
    client.close();
});