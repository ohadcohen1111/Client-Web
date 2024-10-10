import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';
import { Parser } from 'binary-parser';

interface IPacketAck {
    lastArxSec: number;  // 8 bits
    systemMode: number;  // 1 bit
    serverId: number;    // 8 bits
}

export class PacketAck extends Packet {
    public parsedPacket: IPacketAck;

    constructor(header?: PacketHeader, data?: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecAck, header, data, isNewHeaderNeeded);
        this.parsedPacket = this.initializeParsedPacket();
    }
    private initializeParsedPacket(): IPacketAck {
        return {
            lastArxSec: 0,
            systemMode: 0,
            serverId: 0,
        };
    }
    private static parser = new Parser()
        .uint8('lastArxSec')
        .bit1('systemMode')
        .bit7('serverIdHigh')
        .bit1('serverIdLow');

    parseData(): void {
        if (!this.data) {
            throw new Error("Invalid data for PacketAck");
        }

        const parsed = PacketAck.parser.parse(this.data);

        this.parsedPacket.lastArxSec = parsed.lastArxSec;
        this.parsedPacket.systemMode = parsed.systemMode;
        this.parsedPacket.serverId = (parsed.serverIdHigh << 1) | parsed.serverIdLow;
    }

    toBuffer(): Buffer {
        const buffer = Buffer.alloc(3);

        // Write LAST_ARX_SEC (8 bits)
        buffer.writeUInt8(this.parsedPacket.lastArxSec, 0);

        // Write SYSTEM_MODE (1 bit) and first 7 bits of SERVER_ID
        buffer.writeUInt8(((this.parsedPacket.systemMode & 0x01) << 7) | ((this.parsedPacket.serverId >> 1) & 0x7F), 1);

        // Write last bit of SERVER_ID
        buffer.writeUInt8((this.parsedPacket.serverId & 0x01) << 7, 2);

        return Buffer.concat([this.header.toBuffer(), buffer]);
    }
}