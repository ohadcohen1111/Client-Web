import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

enum EUserPriority {
    None = 0,
    Level_1 = 0x0001,
    Level_2 = 0x0002,
    Level_3 = 0x0003,
    Level_4 = 0x0004,
    Level_5 = 0x0005,
    Level_6 = 0x0006,
    Level_7 = 0x0007,
    Level_8 = 0x0008,
    Level_9 = 0x0009,
    Level_10 = 0x000A,
    Level_11 = 0x000B,
    Level_12 = 0x000C,
    Level_13 = 0x000D,
    Level_14 = 0x000E,
    Level_15 = 0x000F,
    Last = 0x019,
    PriorityLast = Last,
    PriorityNormal = PriorityLast + 0x0001,
    PriorityHigh = PriorityLast + 0x0002,
    PriorityUrgent = PriorityLast + 0x0003,
    PriorityEmergency = PriorityLast + 0x0004,
    USER_PRIORITY_MAX_VAL = 0x0020
}

export class PacketDisablePtt extends Packet {
    private sessionId: bigint = 0n;
    private randomVal: number = 0;
    private talkerId: bigint = 0n;
    private talkerName: string = '';
    private deviceId: bigint = 0n;
    private talkerPriority: EUserPriority = EUserPriority.None;
    private alert: boolean = false;

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecDisablePTT, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        this.sessionId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;

        this.randomVal = readBits(buffer, bitOffset, 32);
        bitOffset += 32;

        this.talkerId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;

        this.talkerName = this.readStringFromBuffer(buffer, bitOffset, 104);
        bitOffset += 104;

        this.deviceId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;

        this.talkerPriority = readBits(buffer, bitOffset, 5) as EUserPriority;
        bitOffset += 5;

        this.alert = readBits(buffer, bitOffset, 1) !== 0;
    }

    toBuffer(): Buffer {
        const body = Buffer.alloc(42);  // 334 bits = 42 bytes (rounded up)
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, this.sessionId, 64, state);
        writeBits(body, this.randomVal, 32, state);
        writeBits(body, this.talkerId, 64, state);
        //this.writeStringToBuffer(body, this.talkerName, 104, state);
        writeBits(body, this.deviceId, 64, state);
        writeBits(body, this.talkerPriority, 5, state);
        writeBits(body, this.alert ? 1 : 0, 1, state);

        return Buffer.concat([this.header.toBuffer(), body]);
    }


    setSessionID(sessionId: bigint): void { this.sessionId = sessionId; }
    getSessionID(): bigint { return this.sessionId; }

    setRandomVal(randVal: number): void { this.randomVal = randVal; }
    getRandomVal(): number { return this.randomVal; }

    setTalkerID(talkerId: bigint): void { this.talkerId = talkerId; }
    getTalkerID(): bigint { return this.talkerId; }

    setTalkerName(talkerName: string): void { this.talkerName = talkerName; }
    getTalkerName(): string { return this.talkerName; }

    setDeviceId(deviceId: bigint): void { this.deviceId = deviceId; }
    getDeviceId(): bigint { return this.deviceId; }

    setTalkerPriority(priority: EUserPriority): void { this.talkerPriority = priority; }
    getTalkerPriority(): EUserPriority { return this.talkerPriority; }

    setAlert(alert: boolean): void { this.alert = alert; }
    getAlert(): boolean { return this.alert; }

    printInfo(): void {
        console.log("Disable PTT Packet:");
        console.log(`Session ID: ${this.sessionId}`);
        console.log(`Random Value: ${this.randomVal}`);
        console.log(`Talker ID: ${this.talkerId}`);
        console.log(`Talker Name: ${this.talkerName}`);
        console.log(`Device ID: ${this.deviceId}`);
        console.log(`Talker Priority: ${EUserPriority[this.talkerPriority]}`);
        console.log(`Alert: ${this.alert}`);
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

    private readStringFromBuffer(buffer: Buffer, startBit: number, numBits: number): string {
        const bytes = Math.ceil(numBits / 8);
        const stringBuffer = buffer.slice(startBit / 8, startBit / 8 + bytes);
        return stringBuffer.toString('utf8').replace(/\0+$/, '');
    }

    // private writeStringToBuffer(buffer: Buffer, str: string, startBit: number, numBits: number): void {
    //     const bytes = Math.ceil(numBits / 8);
    //     const stringBuffer = Buffer.alloc(bytes);
    //     stringBuffer.write(str, 'utf8');
    //     for (let i = 0; i < numBits; i++) {
    //         const srcByte = stringBuffer[Math.floor(i / 8)];
    //         const srcBit = (srcByte & (1 << (7 - (i % 8)))) !== 0;
    //         writeBits(buffer, srcBit ? 1 : 0, startBit + i, 1);
    //     }
    // }

    static getDataFormat(): number[] {
        return [64, 32, 64, 104, 64, 5, 1];
    }
}