import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

export class PacketEnablePtt extends Packet {
    private sessionId: bigint = 0n;

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecEnablePTT, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        this.sessionId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
    }

    toBuffer(): Buffer {
        const body = Buffer.alloc(8);  // 64 bits = 8 bytes
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, this.sessionId, 64, state);

        return Buffer.concat([this.header.toBuffer(), body]);
    }

    setSessionID(sessionId: bigint): void {
        this.sessionId = sessionId;
    }

    getSessionID(): bigint {
        return this.sessionId;
    }

    printInfo(): void {
        console.log("Enable PTT Packet:");
        console.log(`Session ID: ${this.sessionId}`);
    }

    private readBigIntFromBuffer(buffer: Buffer, startBit: number, numBits: number): bigint {
        let value = BigInt(0);
        for (let i = 0; i < numBits; i++) {
            const byteIndex = Math.floor((startBit + i) / 8);
            const bitIndex = (startBit + i) % 8;
            const bit = (buffer[byteIndex] & (1 << (7 - bitIndex))) !== 0;
            value = (value << BigInt(1)) | BigInt(bit ? 1 : 0);
        }
        return value;
    }

    static getDataFormat(): number[] {
        return [64]; // Representing 64 bits for session id
    }
}