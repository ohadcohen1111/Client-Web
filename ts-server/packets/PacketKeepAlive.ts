import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';
import { deviceId as constantDeviceId } from '../constants';

export class PacketKeepAlive extends Packet {
    private expectReply: boolean = true;
    private deviceId: bigint = constantDeviceId.value;

    constructor(header?: PacketHeader, data?: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecKeepAlive, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let state = { offset: 0, bitOffset: 0 };

        //this.expectReply = Boolean(readBits(buffer, 1, state));
        this.deviceId = this.readBigIntFromBuffer(buffer, state.bitOffset, 64);
    }

    toBuffer(): Buffer {
        const body = Buffer.alloc(9);  // 1 bit + 64 bits = 9 bytes
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, this.expectReply ? 1 : 0, 1, state);
        writeBits(body, this.deviceId, 64, state);

        return Buffer.concat([this.header.toBuffer(), body]);
    }

    setExpectReply(value: boolean): void {
        this.expectReply = value;
    }

    getExpectReply(): boolean {
        return this.expectReply;
    }

    setDeviceId(value: bigint): void {
        this.deviceId = value;
    }

    getDeviceId(): bigint {
        return this.deviceId;
    }

    printInfo(): void {
        console.log("Keep Alive Packet:");
        console.log(`Expect Reply: ${this.expectReply}`);
        console.log(`Device ID: ${this.deviceId}`);
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
        return [1, 64]; // Representing 1 bit for expectReply and 64 bits for deviceId
    }
}