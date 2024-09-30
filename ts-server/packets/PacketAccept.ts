import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

export class PacketAccept extends Packet {
    private sessionId: bigint = 0n;

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean = false) {
        super(ECommand.ecAccept, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        this.sessionId = BigInt(readBits(buffer, bitOffset, 64));
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
        console.log("Accept Packet:");
        console.log(`Session ID: ${this.sessionId}`);
    }
}