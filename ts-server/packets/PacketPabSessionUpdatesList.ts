import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, writeBits, readBits } from '../utils';

interface SessionUpdate {
    contactId: bigint;
    sessionId: bigint;
    isJoin: boolean;
}

export class PacketPabSessionUpdatesList extends Packet {
    private static readonly MAX_RECORDS = 30;
    private records: SessionUpdate[] = [];

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean = false) {
        super(ECommand.ecPABSessionUpdatesList, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        // Convert Uint8Array to Buffer
        const buffer = Buffer.from(this.data);

        const state = { bitOffset: 0 };

        while (state.bitOffset < buffer.length * 8 && this.records.length < PacketPabSessionUpdatesList.MAX_RECORDS) {
            const contactId = BigInt(readBits(buffer, state.bitOffset, 64));
            state.bitOffset += 64;
            const sessionId = BigInt(readBits(buffer, state.bitOffset, 64));
            state.bitOffset += 64;
            const isJoin = Boolean(readBits(buffer, state.bitOffset, 1));
            state.bitOffset += 1;

            this.records.push({ contactId, sessionId, isJoin });
        }
    }

    toBuffer(): Buffer {
        const bufferSize = this.records.length * (64 + 64 + 1) / 8; // 64 bits for contactId, 64 for sessionId, 1 for isJoin
        const buffer = Buffer.alloc(bufferSize);
        const state = { bitOffset: 0, offset: 0 };

        for (const record of this.records) {
            writeBits(buffer, record.contactId, 64, state);
            writeBits(buffer, record.sessionId, 64, state);
            writeBits(buffer, record.isJoin ? 1 : 0, 1, state);
        }

        return buffer.slice(0, Math.ceil(state.bitOffset / 8));
    }

    getRecord(idx: number): SessionUpdate | null {
        if (idx >= 0 && idx < this.records.length) {
            return this.records[idx];
        }
        return null;
    }

    getMaxRecords(): number {
        return PacketPabSessionUpdatesList.MAX_RECORDS;
    }

    getNumRecords(): number {
        return this.records.length;
    }

    printInfo(): void {
        console.log("PAB Session Updates List");
        console.log(`Number of records: ${this.records.length}`);
        this.records.forEach((record, index) => {
            console.log(`Record ${index}:`);
            console.log(`  Contact ID: ${record.contactId}`);
            console.log(`  Session ID: ${record.sessionId}`);
            console.log(`  Is Join: ${record.isJoin ? 'Yes' : 'No'}`);
        });
    }
}