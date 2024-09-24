import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

interface PabGroupRecord {
    id: bigint;
    name: string;
    type: number;
    opcode: number;
}

export class PacketPabGroupList extends Packet {
    private static readonly MAX_RECORDS = 15;
    private static readonly GROUP_NAME_LENGTH = 12; // 96 bits / 8 bits per byte
    private static readonly PAB_GROUP_FMT = 263; // 64 + 96 + 3 + 4 bits

    private groups: PabGroupRecord[] = [];

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecPABGroupList, header, data);
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

        for (let i = 0; i < PacketPabGroupList.MAX_RECORDS; i++) {
            const id = view.getBigUint64(offset, false); // false for big-endian
            offset += 8;

            const nameBuffer = new Uint8Array(this.data.buffer, offset, PacketPabGroupList.GROUP_NAME_LENGTH);
            const name = new TextDecoder().decode(nameBuffer).replace(/\0+$/, ''); // Remove null terminators
            offset += PacketPabGroupList.GROUP_NAME_LENGTH;

            const typeByte = view.getUint8(offset);
            const type = typeByte >> 5; // Top 3 bits
            const opcode = typeByte & 0x0F; // Bottom 4 bits
            offset += 1;

            this.groups.push({ id, name, type, opcode });

            // Check if we've reached the end of the data
            if (offset >= this.data.length) break;
        }
    }

    getGroups(): PabGroupRecord[] {
        return this.groups;
    }

    // We still need to implement this abstract method from the Packet class,
    // but we can make it throw an error since we don't use it
    toBuffer(): Buffer {
        throw new Error("PacketPABGroupList is for receiving only and cannot be converted to a buffer");
    }
}