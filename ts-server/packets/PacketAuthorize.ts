import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { Parser } from 'binary-parser';
import { ECommand, getSIPMethod, bufferToString } from '../utils';
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
    public parsedPacket: IPacketAuthorize;
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

    private static parser = new Parser()
        .endianess('big')
        .bit4('algorithm')
        .bit4('uri')
        .buffer('authMethod', { length: 63 })
        .bit8('rfu1')
        .buffer('realm', { length: 63 })
        .bit32('nonce')
        .bit32('opaque')
        .bit1('method', { length: 16 })
        .buffer('response', { length: 16 })
        .buffer('username', { length: 63 })
        .uint64('eauthDeviceId')
        .bit4('eauthPassType')

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }
        const parsed = PacketAuthorize.parser.parse(this.data);

        this.parsedPacket.algorithm = parsed.algorithm;
        this.parsedPacket.authMethod = parsed.authMethod;
        this.parsedPacket.uri = bufferToString(parsed.uri);
        this.parsedPacket.rfu1 = parsed.rfu1;
        this.parsedPacket.realm = bufferToString(parsed.realm);
        this.parsedPacket.nonce = parsed.nonce;
        this.parsedPacket.opaque = parsed.opaque;
        this.parsedPacket.method = bufferToString(parsed.method);
        this.parsedPacket.response = bufferToString(parsed.response);
        this.parsedPacket.username = bufferToString(parsed.username);
        this.parsedPacket.eauthDeviceId = BigInt(parsed.eauthDeviceId);
        this.parsedPacket.eauthPassType = parsed.eauthPassType;
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