import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

export class PacketParser {
    static parseCommand(header: PacketHeader, buffer: Buffer): ECommand {
        if (header.command === ECommand.ecPlaceSavedForReachMe) {
            return buffer[PacketHeader.HEADER_SIZE] as ECommand;
        }
        return header.command;
    }

    static getTotalHeaderSize(header: PacketHeader): number {
        return PacketHeader.HEADER_SIZE + (header.command === ECommand.ecPlaceSavedForReachMe ? 1 : 0);
    }

    static parsePacket(buffer: Buffer): { header: PacketHeader, data: Buffer } {
        const header = PacketHeader.fromBuffer(buffer.slice(0, PacketHeader.HEADER_SIZE));
        const totalHeaderSize = this.getTotalHeaderSize(header);
        if (totalHeaderSize > 23) {
            console.log(totalHeaderSize);
        }
        const command = this.parseCommand(header, buffer);

        // If it's an extended header, update the command in the header
        if (header.command !== command) {
            header.command = command;
        }

        return {
            header: header,
            data: buffer.slice(totalHeaderSize)
        };
    }
}