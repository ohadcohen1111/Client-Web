import { Parser } from 'binary-parser';

interface IPacketAudio {
    // Common header part
    protocolVersion: number;
    recipientId: bigint;
    senderId: bigint;

    // Audio-specific header part
    sessionId: bigint;
    vocoder: number;
    serialNumber: number;
    originalSize: number;

    // Audio data
    audioData: Buffer;
}

export class PacketAudio {
    public parsedPacket: IPacketAudio;

    constructor(data?: Buffer) {
        this.parsedPacket = this.initializeParsedPacket();
        if (data) {
            this.parseData(data);
        }
    }

    private initializeParsedPacket(): IPacketAudio {
        return {
            protocolVersion: 0,
            recipientId: 0n,
            senderId: 0n,
            sessionId: 0n,
            vocoder: 0,
            serialNumber: 0,
            originalSize: 0,
            audioData: Buffer.alloc(0)
        };
    }

    private static parser = new Parser()
        .endianess('big')
        .uint32('protocolVersion')
        .uint64('recipientId')
        .uint64('senderId')
        .uint64('sessionId')
        .uint16('vocoder')
        .uint16('serialNumber')
        .uint16('originalSize')
        .buffer('audioData', { readUntil: 'eof' });

    public parseData(data: Buffer): void {
        const parsed = PacketAudio.parser.parse(data);

        this.parsedPacket.protocolVersion = parsed.protocolVersion;
        this.parsedPacket.recipientId = parsed.recipientId;
        this.parsedPacket.senderId = parsed.senderId;
        this.parsedPacket.sessionId = parsed.sessionId;
        this.parsedPacket.vocoder = parsed.vocoder;
        this.parsedPacket.serialNumber = parsed.serialNumber;
        this.parsedPacket.originalSize = parsed.originalSize;
        this.parsedPacket.audioData = parsed.audioData;
    }

    public toBuffer(): Buffer {
        const buffer = Buffer.alloc(34 + this.parsedPacket.audioData.length);
        let offset = 0;

        buffer.writeUInt32BE(this.parsedPacket.protocolVersion, offset);
        offset += 4;

        buffer.writeBigUInt64BE(this.parsedPacket.recipientId, offset);
        offset += 8;

        buffer.writeBigUInt64BE(this.parsedPacket.senderId, offset);
        offset += 8;

        buffer.writeBigUInt64BE(this.parsedPacket.sessionId, offset);
        offset += 8;

        buffer.writeUInt16BE(this.parsedPacket.vocoder, offset);
        offset += 2;

        buffer.writeUInt16BE(this.parsedPacket.serialNumber, offset);
        offset += 2;

        buffer.writeUInt16BE(this.parsedPacket.originalSize, offset);
        offset += 2;

        this.parsedPacket.audioData.copy(buffer, offset);

        return buffer;
    }

    public toString(): string {
        return `Audio Packet:
            Protocol Version: ${this.parsedPacket.protocolVersion}
            Recipient ID: ${this.parsedPacket.recipientId}
            Sender ID: ${this.parsedPacket.senderId}
            Session ID: ${this.parsedPacket.sessionId}
            Vocoder: ${this.parsedPacket.vocoder}
            Serial Number: ${this.parsedPacket.serialNumber}
            Original Size: ${this.parsedPacket.originalSize}
            Audio Data Length: ${this.parsedPacket.audioData.length} bytes`;
    }
}

// // Usage example
// function parseAudioPacket(data: Buffer): void {
//     const packet = new PacketAudio(data);
//     console.log(packet.toString());
// }

// // Example of creating and using an AudioPacket
// const exampleData = Buffer.alloc(50); // Example buffer with some data
// exampleData.writeUInt32BE(1, 0); // Protocol version
// // ... fill in other fields as needed

// parseAudioPacket(exampleData);