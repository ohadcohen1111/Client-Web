import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

interface PabGroupRecordEx {
    id: bigint;
    name: string;
    type: number;
    opcode: number;
    isLarge: boolean;
    isAffiliated: boolean;
    userIsMuted: boolean;
}

export class PacketPabGroupListEx extends Packet {
    private static readonly MAX_RECORDS = 14;
    private static readonly GROUP_NAME_LENGTH = 12; // 96 bits / 8 bits per byte
    private static readonly PAB_GROUP_FMT_EX = 265; // 64 + 96 + 3 + 4 + 1 + 1 + 1 bits

    private groups: PabGroupRecordEx[] = [];

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecPABGroupListEx, header, data);
        if (data) {
            this.parseData();
        }
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const view = new DataView(this.data.buffer);
        let offset = 0;

        for (let i = 0; i < PacketPabGroupListEx.MAX_RECORDS; i++) {
            const id = view.getBigUint64(offset, false); // false for big-endian
            offset += 8;

            const nameBuffer = new Uint8Array(this.data.buffer, offset, PacketPabGroupListEx.GROUP_NAME_LENGTH);
            const name = new TextDecoder().decode(nameBuffer).replace(/\0+$/, ''); // Remove null terminators
            offset += PacketPabGroupListEx.GROUP_NAME_LENGTH;

            const typeByte = view.getUint8(offset);
            const type = typeByte >> 5; // Top 3 bits
            const opcode = typeByte & 0x0F; // Bottom 4 bits
            offset += 1;

            const flagsByte = view.getUint8(offset);
            const isLarge = (flagsByte & 0x04) !== 0;
            const isAffiliated = (flagsByte & 0x02) !== 0;
            const userIsMuted = (flagsByte & 0x01) !== 0;
            offset += 1;

            this.groups.push({ id, name, type, opcode, isLarge, isAffiliated, userIsMuted });

            // Check if we've reached the end of the data
            if (offset >= this.data.length) break;
        }
    }

    getGroups(): PabGroupRecordEx[] {
        return this.groups;
    }

    // We still need to implement this abstract method from the Packet class,
    // but we can make it throw an error since we don't use it
    toBuffer(): Buffer {
        throw new Error("PacketPabGroupListEx is for receiving only and cannot be converted to a buffer");
    }
}