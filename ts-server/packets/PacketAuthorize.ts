import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, readString, getSIPMethod, writeBits } from '../utils';
import { base64Encode, calcResponse } from '../cryptoUtils';
import { deviceId } from '../constants';

type CPacketAuthorize = {
    ALGORITHM: number;
    AUTH_METHOD: number;
    URI: string;
    RFU1: number;
    REALM: string;
    NONCE: number;
    OPAQUE: number;
    METHOD: string;
    RESPONSE: string;
    USERNAME: string;
    EAUTH_DEVICE_ID: bigint;
    EAUTH_PASS_TYPE: number;
};

export class PacketAuthorize extends Packet {
    private parsedPacket: CPacketAuthorize;
    private prevCommand: ECommand;

    constructor(prevCommand: ECommand, header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecAuthorize, header, data);
        this.prevCommand = prevCommand;
        this.parsedPacket = this.initializeParsedPacket();
    }

    private initializeParsedPacket(): CPacketAuthorize {
        return {
            ALGORITHM: 0,
            AUTH_METHOD: 0,
            URI: '',
            RFU1: 0,
            REALM: '',
            NONCE: 0,
            OPAQUE: 0,
            METHOD: '',
            RESPONSE: '',
            USERNAME: '',
            EAUTH_DEVICE_ID: 0n,
            EAUTH_PASS_TYPE: 0
        };
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;
        this.parsedPacket = {
            ALGORITHM: readBits(buffer, bitOffset, 4),
            AUTH_METHOD: readBits(buffer, bitOffset += 4, 4),
            URI: readString(buffer, bitOffset += 4, 504),
            RFU1: readBits(buffer, bitOffset += 504, 8),
            REALM: readString(buffer, bitOffset += 8, 504),
            NONCE: readBits(buffer, bitOffset += 504, 32),
            OPAQUE: readBits(buffer, bitOffset += 32, 32),
            METHOD: readString(buffer, bitOffset += 32, 128),
            RESPONSE: readString(buffer, bitOffset += 128, 128),
            USERNAME: readString(buffer, bitOffset += 128, 504),
            EAUTH_DEVICE_ID: BigInt(readBits(buffer, bitOffset += 504, 64)),
            EAUTH_PASS_TYPE: readBits(buffer, bitOffset += 64, 4)
        };
    }

    toBuffer(): Buffer {
        const packetBody = this.createCPacketAuthorize();
        return Buffer.concat([this.header.toBuffer(), packetBody]);
    }

    private createCPacketAuthorize(): Buffer {
        const nonceBuffer = Buffer.alloc(4);
        nonceBuffer.writeUInt32BE(this.parsedPacket.NONCE);
        const base64Nonce = base64Encode(nonceBuffer);

        const username = "999000000000075087";
        const password = "12345";
        const method = getSIPMethod(this.prevCommand);

        const response = calcResponse(
            username,
            this.parsedPacket.REALM,
            password,
            method,
            this.parsedPacket.URI,
            base64Nonce
        );

        const buffer = Buffer.alloc(239);
        let offset = 0;
        let bitOffset = 0;

        function writeBits(value: number | bigint, bits: number) {
            while (bits > 0) {
                const availableBits = 8 - (bitOffset % 8);
                const bitsToWrite = Math.min(availableBits, bits);
                const mask = (1 << bitsToWrite) - 1;
                const shiftedValue = (Number(value) & mask) << (availableBits - bitsToWrite);
                buffer[offset] |= shiftedValue;
                value = Number(value) >> bitsToWrite;
                bits -= bitsToWrite;
                bitOffset += bitsToWrite;
                if (bitOffset % 8 === 0) {
                    offset++;
                }
            }
        }

        function writeString(str: string, maxBytes: number) {
            const buf = Buffer.from(str, 'utf8');
            buf.copy(buffer, offset, 0, Math.min(buf.length, maxBytes));
            offset += maxBytes;
            bitOffset = offset * 8;
        }

        writeBits(this.parsedPacket.ALGORITHM, 4);
        writeBits(this.parsedPacket.AUTH_METHOD, 4);
        writeString(this.parsedPacket.URI, 63);
        writeBits(0, 8);
        writeString(this.parsedPacket.REALM, 63);
        buffer.writeUInt32BE(this.parsedPacket.NONCE, offset);
        offset += 4;
        bitOffset = offset * 8;
        buffer.writeUInt32BE(this.parsedPacket.OPAQUE, offset);
        offset += 4;
        bitOffset = offset * 8;
        writeString(method, 16);
        buffer.write(response, offset, 16, 'hex');
        offset += 16;
        bitOffset = offset * 8;
        writeString(username, 63);

        buffer.writeBigUInt64BE(deviceId.value, offset);

        return buffer;
    }
}