import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

const MAX_ADHOC_IDS = 10;
const IPRS_NAME_DISPLAY_SIZE = 20;

export class PacketCreateAdHoc extends Packet {
    private ids: bigint[] = new Array(MAX_ADHOC_IDS).fill(0n);

    constructor(header?: PacketHeader, data?: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecCreateAdHoc, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        for (let i = 0; i < MAX_ADHOC_IDS; i++) {
            this.ids[i] = this.readBigIntFromBuffer(buffer, bitOffset, 64);
            bitOffset += 64;
        }
    }

    toBuffer(): Buffer {
        const bodySize = MAX_ADHOC_IDS * 8; // 64 bits = 8 bytes per ID
        const body = Buffer.alloc(bodySize);
        let state = { offset: 0, bitOffset: 0 };

        for (let i = 0; i < MAX_ADHOC_IDS; i++) {
            writeBits(body, this.ids[i], 64, state);
        }

        return Buffer.concat([this.header.toBuffer(), body]);
    }

    setID(idx: number, id: bigint): void {
        if (idx >= 0 && idx < MAX_ADHOC_IDS) {
            this.ids[idx] = id;
        } else {
            console.error(`Could not set Ad-Hoc ID, (idx = ${idx})`);
        }
    }

    getID(idx: number): bigint {
        if (idx >= 0 && idx < MAX_ADHOC_IDS) {
            return this.ids[idx];
        } else {
            console.error(`Could not get Ad-Hoc ID, (idx = ${idx})`);
            return 0n;  // Equivalent to TUserID::NoID() in the original code
        }
    }

    printInfo(): void {
        console.log("Create Ad-Hoc Packet:");
        for (let i = 0; i < MAX_ADHOC_IDS; i++) {
            if (this.ids[i] !== 0n) {
                console.log(`ID ${i}: ${this.ids[i]}`);
            }
        }
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
        return Array(MAX_ADHOC_IDS).fill(64);  // 64 bits for each ID
    }
}