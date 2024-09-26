import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, readString, getSIPMethod, writeBits } from '../utils';
import { base64Encode, calcResponse } from '../cryptoUtils';
import { deviceId, password, username } from '../constants';

interface IPacketAuthorize {
    algorithm: number;
    authMethod: number;
    uri: string;
    rfu1: number;
    realm: string;
    nonce: number;
    opaque: number;
    method: string;
    response: string;
    username: string;
    eauthDeviceId: bigint;
    eauthPassType: number;
}

export class PacketAuthorize extends Packet {
    private parsedPacket: IPacketAuthorize;
    private prevCommand: ECommand;

    constructor(prevCommand: ECommand, header?: PacketHeader, data?: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecAuthorize, header, data, isNewHeaderNeeded);
        this.prevCommand = prevCommand;
        this.parsedPacket = this.initializeParsedPacket();
    }

    private initializeParsedPacket(): IPacketAuthorize {
        return {
            algorithm: 0,
            authMethod: 0,
            uri: '',
            rfu1: 0,
            realm: '',
            nonce: 0,
            opaque: 0,
            method: '',
            response: '',
            username: '',
            eauthDeviceId: 0n,
            eauthPassType: 0
        };
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;
        this.parsedPacket.algorithm = readBits(buffer, bitOffset, 4);
        this.parsedPacket.authMethod = readBits(buffer, bitOffset += 4, 4);
        this.parsedPacket.uri = readString(buffer, bitOffset += 4, 504);
        this.parsedPacket.rfu1 = readBits(buffer, bitOffset += 504, 8);
        this.parsedPacket.realm = readString(buffer, bitOffset += 8, 504);
        this.parsedPacket.nonce = readBits(buffer, bitOffset += 504, 32);
        this.parsedPacket.opaque = readBits(buffer, bitOffset += 32, 32);
        this.parsedPacket.method = readString(buffer, bitOffset += 32, 128);
        this.parsedPacket.response = readString(buffer, bitOffset += 128, 128);
        this.parsedPacket.username = readString(buffer, bitOffset += 128, 504);
        this.parsedPacket.eauthDeviceId = BigInt(readBits(buffer, bitOffset += 504, 64));
        this.parsedPacket.eauthPassType = readBits(buffer, bitOffset += 64, 4);
    }

    toBuffer(): Buffer {
        const packetBody = this.createCPacketAuthorize();
        return Buffer.concat([this.header.toBuffer(), packetBody]);
    }

    private createCPacketAuthorize(): Buffer {
        const nonceBuffer = Buffer.alloc(4);
        nonceBuffer.writeUInt32BE(this.parsedPacket.nonce);
        const base64Nonce = base64Encode(nonceBuffer);

        const method = getSIPMethod(this.prevCommand);

        const response = calcResponse(
            username.value,
            this.parsedPacket.realm,
            password.value,
            method,
            this.parsedPacket.uri,
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

        writeBits(this.parsedPacket.algorithm, 4);
        writeBits(this.parsedPacket.authMethod, 4);
        writeString(this.parsedPacket.uri, 63);
        writeBits(0, 8);
        writeString(this.parsedPacket.realm, 63);
        buffer.writeUInt32BE(this.parsedPacket.nonce, offset);
        offset += 4;
        bitOffset = offset * 8;
        buffer.writeUInt32BE(this.parsedPacket.opaque, offset);
        offset += 4;
        bitOffset = offset * 8;
        writeString(method, 16);
        buffer.write(response, offset, 16, 'hex');
        offset += 16;
        bitOffset = offset * 8;
        writeString(username.value, 63);

        buffer.writeBigUInt64BE(deviceId.value, offset);

        return buffer;
    }
}