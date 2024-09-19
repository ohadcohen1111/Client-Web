import { readBits, createFieldReader } from "../utils";

// Define the PacketHeader interface
interface PacketHeader {
    protocolVersion: number;
    recipientID: number;
    senderID: number;
    sequenceMajor: number;
    sequenceMinor: number;
    commandID: number;
    doNotReply: number;
    unUsedBit: number;
}

// PacketHeader implementation class with constructor
class PacketHeaderImpl implements PacketHeader {
    protocolVersion: number;
    recipientID: number;
    senderID: number;
    sequenceMajor: number;
    sequenceMinor: number;
    commandID: number;
    doNotReply: number;
    unUsedBit: number;

    constructor(
        protocolVersion: number,
        recipientID: number,
        senderID: number,
        sequenceMajor: number,
        sequenceMinor: number,
        commandID: number,
        doNotReply: number,
        unUsedBit: number
    ) {
        this.protocolVersion = protocolVersion;
        this.recipientID = recipientID;
        this.senderID = senderID;
        this.sequenceMajor = sequenceMajor;
        this.sequenceMinor = sequenceMinor;
        this.commandID = commandID;
        this.doNotReply = doNotReply;
        this.unUsedBit = unUsedBit;
    }

    // Additional method to display header information as a string
    toString(): string {
        return `ProtocolVersion: ${this.protocolVersion}, RecipientID: ${this.recipientID}, SenderID: ${this.senderID}, SequenceMajor: ${this.sequenceMajor}, SequenceMinor: ${this.sequenceMinor}, CommandID: ${this.commandID}, DoNotReply: ${this.doNotReply}, UnUsedBit: ${this.unUsedBit}`;
    }
}

function parseHeader(buffer: Buffer): PacketHeader {
    const readField = createFieldReader(buffer);

    return {
        protocolVersion: readField(32),
        recipientID: readField(64),
        senderID: readField(64),
        sequenceMajor: readField(8),
        sequenceMinor: readField(8),
        commandID: readField(6),
        doNotReply: readField(1),
        unUsedBit: readField(1),
    };
}

export { PacketHeader, PacketHeaderImpl, parseHeader };
