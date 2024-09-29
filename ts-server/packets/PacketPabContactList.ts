import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits } from '../utils';

const MAGIC = 0xFF;
const PAB_CHAR = 16;  // 16 bits because USE_WIDE_CHAR is defined
const CONTACT_NAME_LENGTH = 12;
const MAX_RECORDS = 15;

enum EUserState {
    OFFLINE = 0x00,
    ONLINE = 0x01,
    PAGEME = 0x02,
    DND = 0x03,
    UNKNOWN = 0x04
}

enum EGroupType {
    EGT_UNDEFINED = 0,
    EGT_CONFERENCE = 1,
    EGT_CHATROOM = 2,
    EGT_PERSONAL = 3,
    EGT_CONTACTLIST = 4,
    EGT_BROADCAST_ORG = 5,
    EGT_GROUP_BROADCAST = 6
}

enum EPABActionCode {
    NOP = 0,
    ADD = 1,
    ADD_MEMBER = 2,
    REMOVE = 3,
    REMOVE_MEMBER = 4,
    UPDATE = 5,
    JOIN = 6,
    LEAVE = 7
}

interface ContactInfo {
    uid: bigint;
    name: string;
    state: EUserState;
    actionCode: EPABActionCode;
    groupId: bigint;
    groupType: EGroupType;
}

export class PacketPabContactList extends Packet {
    private contacts: ContactInfo[] = [];

    constructor(header: PacketHeader, data: Buffer, isNewHeaderNeeded: boolean) {
        super(ECommand.ecPABContactList, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        const numRecords = this.countRecords(buffer);

        for (let i = 0; i < numRecords; i++) {
            const startIndex = i * this.getRecordSize();
            const contact = this.extractContactInfo(buffer, startIndex);
            this.contacts.push(contact);
        }
    }

    private countRecords(buffer: Buffer): number {
        const totalBits = buffer.length * 8;
        const recordSize = this.getRecordSize();
        return Math.min(Math.floor(totalBits / recordSize), MAX_RECORDS);
    }

    private getRecordSize(): number {
        // 64 (UID) + 96 (NAME) + 3 (STATE) + 1 (NICK) + 1 (DUMMY) + 3 (ACTION_CODE) + 64 (GID) + 3 (GROUP_TYPE)
        return 64 + (PAB_CHAR * CONTACT_NAME_LENGTH) + 3 + 1 + 1 + 3 + 64 + 3;
    }

    private extractContactInfo(buffer: Buffer, startBitIndex: number): ContactInfo {
        let bitOffset = startBitIndex;

        const uid = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;

        const name = this.extractName(buffer, bitOffset);
        bitOffset += PAB_CHAR * CONTACT_NAME_LENGTH;

        const state = readBits(buffer, bitOffset, 3) as EUserState;
        bitOffset += 3;

        // Skip NICK and DUMMY
        bitOffset += 2;

        const actionCode = readBits(buffer, bitOffset, 3) as EPABActionCode;
        bitOffset += 3;

        const groupId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;

        const groupType = readBits(buffer, bitOffset, 3) as EGroupType;

        return { uid, name, state, actionCode, groupId, groupType };
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

    private extractName(buffer: Buffer, startBit: number): string {
        let name = "";
        for (let i = 0; i < CONTACT_NAME_LENGTH; i++) {
            const charValue = readBits(buffer, startBit + i * PAB_CHAR, PAB_CHAR);
            if (charValue !== 0) {
                name += String.fromCharCode(charValue);
            }
        }
        return name.trim();
    }

    toBuffer(): Buffer {
        // Implementation for serializing the packet
        // This would be used when sending a PAB Contact List packet
        // For now, we'll return an empty buffer as it's primarily used for parsing
        return Buffer.alloc(0);
    }

    printContacts(): void {
        console.log(`Number of contacts: ${this.contacts.length}`);
        console.log(`Record size: ${this.getRecordSize()} bits`);
        console.log("\nContact Information:");

        this.contacts.forEach((contact, index) => {
            console.log(`\nContact ${index + 1}:`);
            console.log(`  UID: ${contact.uid}`);
            console.log(`  Name: "${contact.name}"`);
            console.log(`  State: ${EUserState[contact.state]} (${contact.state})`);
            console.log(`  Action: ${EPABActionCode[contact.actionCode]} (${contact.actionCode})`);
            console.log(`  Group ID: ${contact.groupId}`);
            console.log(`  Group Type: ${EGroupType[contact.groupType]} (${contact.groupType})`);
            console.log("---------------------------------");
        });
    }
}