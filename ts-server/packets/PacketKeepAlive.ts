import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';


export class PacketKeepAlive extends Packet {

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecKeepAlive, header, data);
    }


    parseData(): void {
        // no implementation required 
    }

    toBuffer(): Buffer {
        return this.header.toBuffer();
    }
}