import os from 'os';
import { Packet } from './packets/Packet';

/**
 * Generic function to write a value into a buffer at a specific bit position
 * @param {Buffer} buffer - The buffer to write into
 * @param {number | bigint} value - The value to write (can be number or BigInt)
 * @param {number} bitOffset - The bit position to start writing
 * @param {number} numBits - The number of bits to write
 */
export function writeBits(
    body: Buffer,
    value: number | bigint,
    bits: number,
    state: { bitOffset: number; offset: number }
): void {
    let { bitOffset, offset } = state;
    const isBigInt = typeof value === 'bigint';

    while (bits > 0) {
        const availableBits = 8 - (bitOffset % 8);
        const bitsToWrite = Math.min(availableBits, bits);
        const mask = (1n << BigInt(bitsToWrite)) - 1n;

        // Shift based on whether the value is BigInt or Number
        const shiftedValue = isBigInt
            ? (value >> BigInt(bits - bitsToWrite)) & mask
            : (value >> (bits - bitsToWrite)) & Number(mask);

        // Write the shifted value to the buffer
        body[offset] |= Number(shiftedValue) << (availableBits - bitsToWrite);

        bitOffset += bitsToWrite;
        bits -= bitsToWrite;

        if (bitOffset % 8 === 0) {
            offset++;
        }
    }

    // Update the state with new values of offset and bitOffset
    state.bitOffset = bitOffset;
    state.offset = offset;
}

export function getCurrentTimeMs(): bigint {
    return BigInt(Math.floor(os.uptime() * 1000));
}

/**
 * Function to read a value from a buffer starting at a given bit offset
 * @param {Buffer} buffer - The buffer to read from
 * @param {number} bitOffset - The bit position to start reading from
 * @param {number} numBits - The number of bits to read
 * @returns {number} - The read value
 */
export function readBits(buffer: Buffer, bitOffset: number, numBits: number): number {
    let byteOffset = Math.floor(bitOffset / 8);
    let bitPosition = bitOffset % 8;
    let value = 0;

    for (let i = 0; i < numBits; i++) {
        const byte = buffer[byteOffset];
        const bit = (byte >> (7 - bitPosition)) & 1;
        value = (value << 1) | bit;

        bitPosition++;
        if (bitPosition === 8) { // Move to the next byte
            bitPosition = 0;
            byteOffset++;
        }
    }

    return value;
}

/**
 * Helper function to create a field reader for a buffer that automatically updates the offset.
 * @param {Buffer} buffer - The buffer to read from.
 * @returns {Function} - A function to read fields with automatic offset management.
 */
export function createFieldReader(buffer: Buffer) {
    let offset = 0;

    return function readNextField(numBits: number): number {
        const value = readBits(buffer, offset, numBits);
        offset += numBits; // Automatically update offset
        return value;
    };
}

export function readString(buffer: Buffer, bitOffset: number, numBits: number): string {
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
 * Function to map command codes to SIP methods
 * @param {number} cmd - The command code to map
 * @returns {string} - The corresponding SIP method
 */
export function getSIPMethod(cmd: number): string {
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
        case 8: // ecApproved
            return "APPROVED";
        case 9: // ecPocUriAction
        case 10: // ecCreateAdHoc
        case 11: // ecCreateAdHocEx
        case 12: // ecRedirectJoin
        case 13: // ecJoinEx
        case 14: // ecJoin
        case 15: // ecPending
        case 16: // ecNewSession
            return "INVITE";
        case 17: // ecLeave
        case 18: // ecEndSession
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

// Define ECommand as an enum in TypeScript for better typing and safety
export enum ECommand {
    /*general*/
    ecNull = 0,
    ecAck = 1,
    ecReRegister = 2,
    ecServerBusy = 3,
    ecKeepAlive = 4,
    /*registration*/
    ecRegister = 5,
    ecUnregister = 6,
    ecApproved = 7,
    ecDenied = 8,
    /*session*/
    ecJoin = 9,
    ecCreateAdHoc = 10,
    ecLeave = 11,
    ecNewSession = 12,
    ecEndSession = 13,
    ecEnablePTT = 14,
    ecDisablePTT = 15,
    ecAccept = 16,
    ecReject = 17,
    ecPending = 18,
    ecError = 19,
    ecDirSesLog = 20,
    /*PAB*/
    ecPABSyncRequest = 21,
    ecPABGroupList = 22,
    ecPABContactList = 23,
    ecPABGroupIDList = 24,
    ecPABStateList = 25,
    ecPABSessionUpdatesList = 26,
    ecPABSearch = 27,
    ecPABSearchResults = 28,
    ecRedirectJoin = 29,
    ecRemoteUpdateContact = 30,
    ecPABSearchOrg = 31,
    ecPABSearchOrgResults = 32,
    ecForward = 35,
    ecJoinEx = 36,
    ecPocUriAction = 37,
    ecAuthorize = 38,
    ecSosAction = 39,
    ecFloorGranted = 40,
    ecPABSubscribe = 41,
    ecPABUnsubscribe = 42,
    ecRemoteActions = 43,
    ecAddToSession = 44,
    ecSessionRefresh = 45,
    ecOpenChannel = 46,
    ecCreateAdHocEx = 47,
    ecPublish = 48,
    ecControlPTT = 49,
    ecSubscribe = 50,
    ecSessionInfo = 51,
    ecGroupSessionInfo = 55,
    ecServiceDiscovery = 56,
    ecDispatcherRequest = 57,
    ecUserLog = 58,
    ecGroupInChargeSiteUpdate = 59,
    ecSiteBackOnline = 60,
    ecUpgradeVersion = 61,
    ecPABReachMeList = 62,
    ecPlaceSavedForReachMe = 63,
    ecNack = 64,
    ecMoveSiteByOrg = 69,
    ecReachMeGroup = 70,
    ecChangeCallInitiator = 71,
    ecGroupAction = 72,
    ecSiteList = 73,
    ecPABRequest = 74,
    ecAuthLongToken = 75,
    ecPasswordDenied = 76,
    ecGroupOneToOneSession = 77,
    ecRecorderStatistic = 78,
    ecPABGroupListEx = 79,
    ecLast = 76 // Adjust according to the highest command
}

export function getCommandString(commandID: number): string {
    // Check if the commandID is a valid key in the ECommand enum
    if (commandID in ECommand) {
        return ECommand[commandID];
    }
    return `UnknownCommand(${commandID})`; // Fallback for unknown commands
}

export function printPacket(packet: Buffer | Packet, action: string) {
    let bitString: string;
    let byteCount: number;

    if (Buffer.isBuffer(packet)) {
        byteCount = packet.length;
        bitString = Array.from(packet)
            .map(byte => byte.toString(2).padStart(8, '0'))
            .join(' ');
    } else {
        const packetBuffer = packet.toBuffer();
        byteCount = packetBuffer.length;
        bitString = Array.from(packetBuffer)
            .map(byte => byte.toString(2).padStart(8, '0'))
            .join(' ');
    }

    console.log('=============');
    console.log(`The packet that was ${action} (bits):\nNumber of bytes: ${byteCount}`);
    console.log(bitString);
    console.log('=============');
}