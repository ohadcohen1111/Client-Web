const dgram = require('dgram');
const { toBufferBE } = require('bigint-buffer');
const crypto = require('crypto');
const client = dgram.createSocket('udp4');

// Server details
const SERVER_IP = '82.166.254.181';
const SERVER_PORT = 25000;

// Command for ecAuthorize
const COMMAND_AUTHORIZE = 38;

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

// Function to create a new CPacketAuthorize and serialize it into a buffer
function createCPacketAuthorize(algorithm, authMethod, uri, realm, nonce, opaque, method, response, username, deviceId, passType) {
    const buffer = Buffer.alloc(1024);  // Allocate enough space for the packet
    let offset = 0;

    // Write fields into the buffer (bit-aligned)
    buffer.writeUInt8(algorithm, offset);
    offset += 4;  // 4 bits for ALGORITHM

    buffer.writeUInt8(authMethod, offset);
    offset += 4;  // 4 bits for AUTH_METHOD

    buffer.write(uri, offset, 'utf8');
    offset += 63;  // URI: 63 bytes

    buffer.writeUInt8(0, offset);  // RFU1 (8 bits)
    offset += 1;

    buffer.write(realm, offset, 'utf8');
    offset += 63;  // REALM: 63 bytes

    buffer.writeUInt32BE(nonce, offset);
    offset += 4;  // NONCE: 32 bits

    buffer.writeUInt32BE(opaque, offset);
    offset += 4;  // OPAQUE: 32 bits

    buffer.write(method, offset, 'utf8');
    offset += 16;  // METHOD: 16 bytes

    buffer.write(response, offset, 'hex');
    offset += 16;  // RESPONSE: 16 bytes (in hex)

    buffer.write(username, offset, 'utf8');
    offset += 63;  // USERNAME: 63 bytes

    buffer.writeBigInt64BE(BigInt(deviceId), offset);
    offset += 8;  // EAUTH_DEVICE_ID: 64 bits

    buffer.writeUInt8(passType, offset);
    offset += 4;  // EAUTH_PASS_TYPE: 4 bits

    console.log(`Client -> Server: Sending CPacketAuthorize (${buffer.length} bytes)`);
    return buffer.slice(0, offset);  // Return the actual size buffer
}

// Function to parse the CPacketAuthorize packet in bits
function parseCPacketAuthorize(buffer) {
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

    console.log('Parsed CPacketAuthorize:');
    console.log('----------------------------');
    for (const [key, value] of Object.entries(parsedPacket)) {
        if (typeof value === 'number') {
            console.log(`${key}: ${value} (${value.toString(16)}h)`);
        } else {
            console.log(`${key}: ${value}`);
        }
    }

    // Set username and password for response calculation
    const username = "odisp@ohad.com";
    const password = "12345";

    // Calculate the response
    const response = calcResponse(
        username,
        parsedPacket.REALM,  // Take realm from packet
        password,
        parsedPacket.METHOD,  // Take method from packet
        parsedPacket.URI,     // Take URI from packet
        parsedPacket.NONCE    // Take nonce from packet
    );

    console.log('Calculated Response:', response);

    // Now send the new CPacketAuthorize back to the server
    const cPacketAuthorize = createCPacketAuthorize(
        parsedPacket.ALGORITHM,
        parsedPacket.AUTH_METHOD,
        parsedPacket.URI,
        parsedPacket.REALM,
        parsedPacket.NONCE,
        parsedPacket.OPAQUE,
        parsedPacket.METHOD,
        response,              // The calculated response
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
        parseCPacketAuthorize(body);
    } else {
        console.log(`Received unknown command: ${command}`);
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
