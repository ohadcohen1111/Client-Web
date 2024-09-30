import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, writeBits, readBits } from '../utils';

enum EUserState {
    OFFLINE = 0,
    ONLINE = 1,
    PAGEME = 2,
    DND = 3,
    UNKNOWN = 4
}

interface ContactState {
    contactId: bigint;
    state: EUserState;
}

export class PacketPabStateList extends Packet {
    private static readonly MAX_RECORDS = 61;
    private records: ContactState[] = [];

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean) {
        super(ECommand.ecPABStateList, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        const state = { bitOffset: 0, offset: 0 };

        while (state.offset < buffer.length && this.records.length < PacketPabStateList.MAX_RECORDS) {
            const contactId = this.readBigIntFromBuffer(buffer, state.bitOffset);
            state.bitOffset += 64;
            state.offset = Math.floor(state.bitOffset / 8);

            const userState = readBits(buffer, state.bitOffset, 3) as EUserState;
            state.bitOffset += 3;
            state.offset = Math.floor(state.bitOffset / 8);

            this.records.push({ contactId, state: userState });
        }
    }

    toBuffer(): Buffer {
        const bufferSize = this.records.length * (64 + 3) / 8; // 64 bits for contactId, 3 for state
        const buffer = Buffer.alloc(bufferSize);
        const state = { bitOffset: 0, offset: 0 };

        for (const record of this.records) {
            writeBits(buffer, record.contactId, 64, state);
            writeBits(buffer, record.state, 3, state);
        }

        return buffer.slice(0, state.offset + (state.bitOffset % 8 > 0 ? 1 : 0));
    }

    setContactID(idx: number, contactId: bigint): void {
        if (idx >= 0 && idx < PacketPabStateList.MAX_RECORDS) {
            if (idx >= this.records.length) {
                this.records[idx] = { contactId, state: EUserState.OFFLINE };
            } else {
                this.records[idx].contactId = contactId;
            }
        }
    }

    getContactID(idx: number): bigint | null {
        if (idx >= 0 && idx < this.records.length) {
            return this.records[idx].contactId;
        }
        return null;
    }

    setContactState(idx: number, state: EUserState): void {
        if (idx >= 0 && idx < PacketPabStateList.MAX_RECORDS) {
            if (idx >= this.records.length) {
                this.records[idx] = { contactId: 0n, state };
            } else {
                this.records[idx].state = state;
            }
        }
    }

    getContactState(idx: number): EUserState | null {
        if (idx >= 0 && idx < this.records.length) {
            return this.records[idx].state;
        }
        return null;
    }

    getMaxRecords(): number {
        return PacketPabStateList.MAX_RECORDS;
    }

    getNumRecords(): number {
        return this.records.length;
    }

    printInfo(): void {
        console.log("PAB State List");
        console.log(`Number of records: ${this.records.length}`);
        this.records.forEach((record, index) => {
            console.log(`Record ${index}:`);
            console.log(`  Contact ID: ${record.contactId}`);
            console.log(`  State: ${EUserState[record.state]} (${record.state})`);
        });
    }

    private readBigIntFromBuffer(buffer: Buffer, startBit: number): bigint {
        let value = BigInt(0);
        for (let i = 0; i < 64; i++) {
            const byteIndex = Math.floor((startBit + i) / 8);
            const bitIndex = (startBit + i) % 8;
            const bit = (buffer[byteIndex] & (1 << (7 - bitIndex))) !== 0;
            value = (value << BigInt(1)) | BigInt(bit ? 1 : 0);
        }
        return value;
    }
}