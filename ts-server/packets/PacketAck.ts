import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

export class PacketAck extends Packet {
    private lastArxSec: number = 0;  // 8 bits
    private systemMode: number = 0;  // 1 bit
    private serverId: number = 0;    // 8 bits

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecAck, header, data);
        if (data) {
            this.parseData();
        }
    }

    parseData(): void {
        if (!this.data || this.data.length < 3) {
            throw new Error("Invalid data for PacketAck");
        }

        const view = new DataView(this.data.buffer);
        
        // Read LAST_ARX_SEC (8 bits)
        this.lastArxSec = view.getUint8(0);

        // Read SYSTEM_MODE (1 bit) and SERVER_ID (8 bits)
        const combinedByte = view.getUint8(1);
        this.systemMode = (combinedByte & 0x80) >> 7;  // Most significant bit
        this.serverId = ((combinedByte & 0x7F) << 1) | (view.getUint8(2) >> 7);
    }

    toBuffer(): Buffer {
        const buffer = Buffer.alloc(3);
        
        // Write LAST_ARX_SEC (8 bits)
        buffer.writeUInt8(this.lastArxSec, 0);

        // Write SYSTEM_MODE (1 bit) and first 7 bits of SERVER_ID
        buffer.writeUInt8(((this.systemMode & 0x01) << 7) | ((this.serverId >> 1) & 0x7F), 1);

        // Write last bit of SERVER_ID
        buffer.writeUInt8((this.serverId & 0x01) << 7, 2);

        return Buffer.concat([this.header.toBuffer(), buffer]);
    }
}