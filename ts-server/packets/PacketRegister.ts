import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, getCurrentTimeMs, writeBits } from '../utils';
import { deviceId } from "../constants";

class PacketRegister extends Packet {
    constructor(header?: PacketHeader) {
        super(ECommand.ecRegister, header);
    }

    parseData(): void {
        // no implementation required
    }

    toBuffer(): Buffer {
        const body = Buffer.alloc(57);
        deviceId.value = getCurrentTimeMs();
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, 33882126, 32, state);
        writeBits(body, 1208025285, 32, state);
        writeBits(body, 6, 32, state);
        writeBits(body, 587989143, 32, state);
        writeBits(body, 49537, 32, state);
        writeBits(body, 57457, 16, state);
        writeBits(body, 57458, 16, state);
        writeBits(body, 2, 8, state);
        writeBits(body, 0n, 64, state);
        writeBits(body, 0n, 64, state);
        writeBits(body, 0n, 64, state);
        writeBits(body, deviceId.value, 64, state);
        console.log("device id: " + deviceId.value);
        return Buffer.concat([this.header.toBuffer(), body]);
    }
}

export { PacketRegister }