import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';


export class PacketPabSyncRequest extends Packet {

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecPABSyncRequest, header, data);
    }


    parseData(): void {
        // no implementation required 
    }

    toBuffer(): Buffer {
        return this.header.toBuffer();
    }
}