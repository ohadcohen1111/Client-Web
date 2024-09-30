import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

enum EErrorReason {
    eerNone = 0x0000,
    eerBadDefGroup = 0x0001,
    eerJoinBadID = 0x0002,
    eerNoPermission = 0x0003,
    eerJoinOwnID = 0x0004,
    eerUserOffline = 0x0005,
    eerUserBusy = 0x0006,
    eerGroupBusy = 0x0007,
    eerBadPTT = 0x0008,
    eerNoSession = 0x0009,
    eerNotMember = 0x000A,
    eerNoCredit = 0x000B,
    eerIllegalStateForJoin = 0x000C,
    eerNotFound = 0x000D,
    eerInvalidParam = 0x000E,
    eerServerError = 0x000F,
    eerServerConfigError = 0x0010,
    eerMustCreateSession = 0x0011,
    eerNotSupported = 0x0012,
    eerUnauthorized = 0x0013,
    eerTimeout = 0x0014,
    eerPendingTrying = 0x0015,
    eerPendingRinging = 0x0016,
    eerDialogDoesNotExist = 0x0017,
    eerProxyAuthentication = 0x0018,
    eerVocoderError = 0x0019,
    eerPriorityOverride = 0x0020,
    eerSosBetweenDispatchers = 0x0021
}

function getErrorReasonString(reason: EErrorReason): string {
    const errorStrings = {
        [EErrorReason.eerNone]: "No error, all is ok",
        [EErrorReason.eerBadDefGroup]: "Could not join default group, no group ID",
        [EErrorReason.eerJoinBadID]: "Could not join, unrecognized ID",
        [EErrorReason.eerNoPermission]: "Could not join, no permission",
        [EErrorReason.eerJoinOwnID]: "Could not join private session, IDs are the same",
        [EErrorReason.eerUserOffline]: "Could not join private session, not registered",
        [EErrorReason.eerUserBusy]: "Could not join private session, user in busy",
        [EErrorReason.eerGroupBusy]: "Could not join public session, all users are busy",
        [EErrorReason.eerBadPTT]: "Could not handle PTT, not in server based session or floor is already taken",
        [EErrorReason.eerNoSession]: "Could not locate session so session request failed",
        [EErrorReason.eerNotMember]: "Could not join public session, not a member of the group",
        [EErrorReason.eerNoCredit]: "Not enough credits to perform action",
        [EErrorReason.eerIllegalStateForJoin]: "A user can not request join if he is busy - must leave first",
        [EErrorReason.eerNotFound]: "Not found",
        [EErrorReason.eerInvalidParam]: "Invalid parameter",
        [EErrorReason.eerServerError]: "Internal server error",
        [EErrorReason.eerServerConfigError]: "The server could not process the request because the associated data is misconfigured",
        [EErrorReason.eerMustCreateSession]: "Tried to join a session with 'joinExisting' and the session does not exist",
        [EErrorReason.eerNotSupported]: "Operation not supported",
        [EErrorReason.eerUnauthorized]: "Authorization required (e.g. for Register)",
        [EErrorReason.eerTimeout]: "Request timeout",
        [EErrorReason.eerPendingTrying]: "100 trying (used in sip protocol)",
        [EErrorReason.eerPendingRinging]: "180 ringing (used in sip protocol)",
        [EErrorReason.eerDialogDoesNotExist]: "481 Call/Transaction Does Not Exist",
        [EErrorReason.eerProxyAuthentication]: "Proxy authentication required",
        [EErrorReason.eerVocoderError]: "No appropriate vocoder found for session",
        [EErrorReason.eerPriorityOverride]: "Server is processing a higher priority item",
        [EErrorReason.eerSosBetweenDispatchers]: "MDC2000 to MDC2000 SOS is not allowed"
    };

    return errorStrings[reason] || "Unknown error";
}

export class PacketError extends Packet {
    private sessionId: bigint = 0n;
    private reason: EErrorReason = EErrorReason.eerNone;

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecError, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        this.sessionId = BigInt(readBits(buffer, bitOffset, 64));
        bitOffset += 64;
        this.reason = readBits(buffer, bitOffset, 16);
    }

    toBuffer(): Buffer {
        const body = Buffer.alloc(10);  // 64 bits + 16 bits = 80 bits = 10 bytes
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, this.sessionId, 64, state);
        writeBits(body, this.reason, 16, state);

        return Buffer.concat([this.header.toBuffer(), body]);
    }

    setSessionID(sessionId: bigint): void {
        this.sessionId = sessionId;
    }

    getSessionID(): bigint {
        return this.sessionId;
    }

    setReason(reason: EErrorReason): void {
        this.reason = reason;
    }

    getReason(): EErrorReason {
        return this.reason;
    }

    getReasonString(): string {
        return getErrorReasonString(this.reason);
    }

    printInfo(): void {
        console.log("Error Packet:");
        console.log(`Session ID: ${this.sessionId}`);
        console.log(`Error Reason: ${this.getReasonString()} (${this.reason})`);
    }
}