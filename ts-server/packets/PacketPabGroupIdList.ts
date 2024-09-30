import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, writeBits } from '../utils';

export class PacketPabGroupIdList extends Packet {
    private groupId: bigint = 0n;
    private isSession: boolean = false;
    private records: bigint[] = [];

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean) {
        super(ECommand.ecPABGroupIDList, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const state = { bitOffset: 0, offset: 0 };

        // Parse header
        this.groupId = this.readBits(this.data, 64, state);
        this.isSession = Boolean(this.readBits(this.data, 1, state));

        // Parse records
        while (state.offset < this.data.length) {
            const userId = this.readBits(this.data, 64, state);
            if (userId === 0n) {  // Assuming 0 marks the end of the list
                break;
            }
            this.records.push(userId);
        }
    }

    private readBits(array: Uint8Array, numBits: number, state: { bitOffset: number, offset: number }): bigint {
        let result = 0n;
        for (let i = 0; i < numBits; i++) {
            const byteIndex = Math.floor((state.bitOffset + i) / 8);
            const bitIndex = (state.bitOffset + i) % 8;
            const bit = (array[byteIndex] & (1 << (7 - bitIndex))) !== 0;
            result = (result << 1n) | BigInt(bit ? 1 : 0);
        }
        state.bitOffset += numBits;
        state.offset = Math.floor(state.bitOffset / 8);
        return result;
    }

    toBuffer(): Buffer {
        const bufferSize = 8 + 1 + (this.records.length * 8) + 8; // groupId + isSession + records + end marker
        const buffer = Buffer.alloc(bufferSize);
        const state = { bitOffset: 0, offset: 0 };

        writeBits(buffer, this.groupId, 64, state);
        writeBits(buffer, this.isSession ? 1 : 0, 1, state);

        for (const userId of this.records) {
            writeBits(buffer, userId, 64, state);
        }

        // Write end marker (0)
        writeBits(buffer, 0n, 64, state);

        return buffer.slice(0, state.offset + (state.bitOffset > 0 ? 1 : 0));
    }

    printInfo(): void {
        console.log("Ohad HandlePABGroupIDList Start===============");
        console.log(`Group ID: ${this.groupId}`);
        console.log(`Is Session: ${this.isSession ? 'Yes' : 'No'}`);
        console.log(`Number of records: ${this.records.length}`);
        this.records.forEach((userId, index) => {
            console.log(`  Ohad HandlePABGroupIDList User ${index}: ${userId}`);
        });
        console.log("Ohad HandlePABGroupIDList End===============");
    }
}