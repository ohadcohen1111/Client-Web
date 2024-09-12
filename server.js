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

// Helper function to read a specific number of bits
function readBits(buffer, bitOffset, numBits) {
    const binaryString = buffer.toString('binary').split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    const value = parseInt(binaryString.substr(bitOffset, numBits), 2);
    return value;
}

// Helper function to read a string of bits
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

// MD5 hash calculation helper function
function calcMD5(input) {
    return crypto.createHash('md5').update(input).digest('hex');
}

// Function to calculate the response based on parsed values
function calcResponse(username, realm, password, method, uri, nonce) {
    // Calculate H(A1) = MD5(username:realm:password)
    const ha1 = calcMD5(`${username}:${realm}:${password}`);

    // Calculate H(A2) = MD5(method:uri)
    const ha2 = calcMD5(`${method}:${uri}`);

    // Calculate response = MD5(H(A1):nonce:H(A2))
    const response = calcMD5(`${ha1}:${nonce}:${ha2}`);

    return response;
}

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

// Function to create a new CPacketAuthorize and serialize it into a buffer
function createCPacketAuthorize(algorithm, authMethod, uri, realm, nonce, opaque, method, response, username, deviceId, passType) {
    const buffer = Buffer.alloc(240);  // Allocate exactly 1916 bits (240 bytes)
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

    // ALGORITHM (4 bits) and AUTH_METHOD (4 bits)
    writeBits(algorithm, 4);
    writeBits(authMethod, 4);

    // URI (504 bits = 63 bytes)
    writeString(uri, 63);

    // RFU1 (8 bits)
    writeBits(0, 8);

    // REALM (504 bits = 63 bytes)
    writeString(realm, 63);

    // NONCE (32 bits)
    buffer.writeUInt32BE(nonce, offset);  // Write the nonce as is, without Base64 decoding
    offset += 4;
    bitOffset = offset * 8;

    // OPAQUE (32 bits)
    buffer.writeUInt32BE(opaque, offset);
    offset += 4;
    bitOffset = offset * 8;

    // METHOD (128 bits = 16 bytes)
    writeString(method, 16);

    // RESPONSE (128 bits = 16 bytes)
    buffer.write(response, offset, 16, 'hex');
    offset += 16;
    bitOffset = offset * 8;

    // USERNAME (504 bits = 63 bytes)
    writeString(username, 63);

    // EAUTH_DEVICE_ID (64 bits)
    buffer.writeBigUInt64BE(BigInt(deviceId), offset);
    offset += 8;
    bitOffset = offset * 8;

    // EAUTH_PASS_TYPE (4 bits)
    writeBits(passType, 4);

    console.log(`Client -> Server: Sending CPacketAuthorize (${buffer.length} bytes)`);
    return buffer;
}

// Function to parse the CPacketAuthorize packet in bits
function parseCPacketAuthorize(buffer, prevCommand) {
    console.log(`Server -> Client: Received CPacketAuthorize (${buffer.length} bytes)`);

    let bitOffset = 0;

    const parsedPacket = {
        ALGORITHM: readBits(buffer, bitOffset, 4),
        AUTH_METHOD: readBits(buffer, bitOffset += 4, 4),
        URI: readString(buffer, bitOffset += 4, 504),  // 63 bytes = 504 bits
        RFU1: readBits(buffer, bitOffset += 504, 8),
        REALM: readString(buffer, bitOffset += 8, 504), // 63 bytes = 504 bits
        NONCE: readBits(buffer, bitOffset += 504, 32),  // 4 bytes = 32 bits
        OPAQUE: readBits(buffer, bitOffset += 32, 32), // 4 bytes = 32 bits
        METHOD: readString(buffer, bitOffset += 32, 128), // 16 bytes = 128 bits
        RESPONSE: readString(buffer, bitOffset += 128, 128), // 16 bytes = 128 bits
        USERNAME: readString(buffer, bitOffset += 128, 504), // 63 bytes = 504 bits
        EAUTH_DEVICE_ID: readBits(buffer, bitOffset += 504, 64), // 8 bytes = 64 bits
        EAUTH_PASS_TYPE: readBits(buffer, bitOffset += 64, 4)
    };

    // Convert NONCE to Base64
    const nonceBuffer = Buffer.alloc(4);
    nonceBuffer.writeUInt32BE(parsedPacket.NONCE);
    const base64Nonce = base64Encode(nonceBuffer);

    console.log('Parsed CPacketAuthorize:');
    console.log('----------------------------');
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

    // Determine the method based on the previous command
    const method = GetSIPMethod(prevCommand || 0); // Use 0 if no previous command

    // Calculate the response using the Base64 encoded nonce
    const response = calcResponse(
        username,
        parsedPacket.REALM,
        password,
        method,
        parsedPacket.URI,
        base64Nonce  // Use the Base64 encoded nonce here
    );

    console.log('Calculated Response:', response);
    console.log('Method used:', method);

    // Now send the new CPacketAuthorize back to the server
    const cPacketAuthorize = createCPacketAuthorize(
        parsedPacket.ALGORITHM,
        parsedPacket.AUTH_METHOD,
        parsedPacket.URI,
        parsedPacket.REALM,
        parsedPacket.NONCE,  // Pass the nonce as is, not Base64 encoded
        parsedPacket.OPAQUE,
        method,
        response,
        username,
        parsedPacket.EAUTH_DEVICE_ID,
        parsedPacket.EAUTH_PASS_TYPE
    );

    // Send the new CPacketAuthorize to the server
    client.send(cPacketAuthorize, SERVER_PORT, SERVER_IP, (err) => {
        if (err) {
            console.error('Error sending CPacketAuthorize:', err);
        } else {
            console.log('CPacketAuthorize sent successfully');
        }
    });

    return parsedPacket;
}

// Function to handle the incoming packet
function handlePacket(msg) {
    // Extract the command from the header (23rd byte in the message)
    const command = (msg.readUInt8(22) >> 2) & 0x3F; // Extract 6 bits for the command

    console.log(`Command: ${command}`);
    console.log(`Packet Length: ${msg.length} bytes`);

    if (command === COMMAND_AUTHORIZE) {
        console.log('Received ecAuthorize packet');
        // Parse the body of the CPacketAuthorize
        const body = msg.slice(23); // The body starts after the 23-byte header
        parseCPacketAuthorize(body, previousCommand);
    } else {
        console.log(`Received command: ${command}`);
        previousCommand = command; // Update the previous command
    }
}

// Listen for incoming UDP messages
client.on('message', (msg, rinfo) => {
    console.log(`Received message from ${rinfo.address}:${rinfo.port}`);
    handlePacket(msg);
});

// Send an initial packet (Register)
function sendRegisterPacket(sequenceMinor, command) {
    const header = Buffer.alloc(23);

    // Protocol Version (4 bytes)
    header.writeUInt32BE(0x0200001C, 0);

    // Recipient ID (8 bytes, value 0x0000000000000000)
    const recipientID = toBufferBE(BigInt(0x0000000000000000), 8);
    recipientID.copy(header, 4);

    // Sender ID (8 bytes, value 0x0DDD2935029EA54F)
    const senderID = toBufferBE(BigInt('0x0DDD2935029EA54F'), 8);
    senderID.copy(header, 12);

    // Sequence (major) (1 byte)
    header.writeUInt8(0, 20);

    // Sequence (minor) (1 byte)
    header.writeUInt8(sequenceMinor, 21);

    // Command (6 bits) + DoNotReply (1 bit) + NonUse (1 bit)
    header.writeUInt8((command << 2) | 0x0, 22);

    console.log(`Client -> Server: Sending Register packet (${header.length} bytes)`);

    // Send the packet
    client.send(header, SERVER_PORT, SERVER_IP, (err) => {
        if (err) {
            console.error('Error sending Register packet:', err);
        } else {
            console.log('Register packet sent successfully');
        }
    });
}

// Send the initial Register packet
sendRegisterPacket(0, 5); // Command 5 is ecRegister

// Handle any UDP errors
client.on('error', (err) => {
    console.error(`UDP error: ${err}`);
    client.close();
});