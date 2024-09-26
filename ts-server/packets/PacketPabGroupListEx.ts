import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, readString } from '../utils';

interface GroupInfo {
    id: bigint;
    name: string;
    type: number;
    action: number;
    isLarge: boolean;
    isAffiliated: boolean;
    userIsMuted: boolean;
}

export class PacketPabGroupListEx extends Packet {
    private groups: GroupInfo[] = [];
    private readonly GROUP_NAME_LENGTH = 12;
    private readonly PAB_CHAR = 16; // 16 bits because USE_WIDE_CHAR is defined

    constructor(header: PacketHeader, data: Buffer, isNewHeaderNeeded: boolean) {
        super(ECommand.ecPABGroupListEx, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        const numRecords = this.countRecords(buffer);

        for (let i = 0; i < numRecords; i++) {
            const startIndex = i * this.getRecordSize();
            const group = this.extractGroupInfo(buffer, startIndex);
            this.groups.push(group);
        }
    }

    private countRecords(buffer: Buffer): number {
        const totalBits = buffer.length * 8;
        const headerSize = 0; // Assuming no header in the data part
        const recordSize = this.getRecordSize();
        return (totalBits - headerSize) / recordSize;
    }

    private getRecordSize(): number {
        // 64 (ID) + 12 * 16 (Name) + 3 (Type) + 4 (Action) + 1 + 1 + 1 (Flags)
        return 64 + this.GROUP_NAME_LENGTH * this.PAB_CHAR + 3 + 4 + 1 + 1 + 1;
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

    private extractGroupInfo(buffer: Buffer, startBitIndex: number): GroupInfo {
        let bitOffset = startBitIndex;

        const id = this.readBigIntFromBuffer(buffer, bitOffset);
        bitOffset += 64;

        const name = this.extractGroupName(buffer, bitOffset);
        bitOffset += this.GROUP_NAME_LENGTH * this.PAB_CHAR;

        const type = readBits(buffer, bitOffset, 3);
        bitOffset += 3;

        const action = readBits(buffer, bitOffset, 4);
        bitOffset += 4;

        const isLarge = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;

        const isAffiliated = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;

        const userIsMuted = Boolean(readBits(buffer, bitOffset, 1));

        return { id, name, type, action, isLarge, isAffiliated, userIsMuted };
    }

    private extractGroupName(buffer: Buffer, startBit: number): string {
        let name = "";
        for (let i = 0; i < this.GROUP_NAME_LENGTH; i++) {
            const charBits = readBits(buffer, startBit + i * this.PAB_CHAR, this.PAB_CHAR);
            if (charBits !== 0) {
                name += String.fromCharCode(charBits);
            }
        }
        return name.trim();
    }

    toBuffer(): Buffer {
        // Implementation for serializing the packet
        // This would be used when sending a PAB Group List Ex packet
        // For now, we'll return an empty buffer as it's primarily used for parsing
        return Buffer.alloc(0);
    }

    printGroups(): void {
        console.log(`Number of groups: ${this.groups.length}`);
        console.log(`Record size: ${this.getRecordSize()} bits`);
        console.log("\nGroup Information:");

        this.groups.forEach((group, index) => {
            console.log(`\nGroup ${index + 1}:`);
            console.log(`  ID: ${group.id}`);
            console.log(`  Name: "${group.name}"`);
            console.log(`  Type: ${this.getGroupTypeName(group.type)} (${group.type})`);
            console.log(`  Action: ${this.getPabActionName(group.action)} (${group.action})`);
            console.log(`  Is Large: ${group.isLarge ? 'Y' : 'N'}`);
            console.log(`  Is Affiliated: ${group.isAffiliated ? 'Y' : 'N'}`);
            console.log(`  User Is Muted: ${group.userIsMuted ? 'Y' : 'N'}`);
            console.log("---------------------------------");
        });
    }

    private getGroupTypeName(type: number): string {
        const types = [
            "undef", "conf", "chat", "pgrp", "clist", "bcast_org", "group_bcast"
        ];
        return types[type] || "unk";
    }

    private getPabActionName(action: number): string {
        const actions = [
            "nop", "add", "addm", "rem", "remm", "updt", "join", "leave", "large", "small"
        ];
        return actions[action] || "unk";
    }
}