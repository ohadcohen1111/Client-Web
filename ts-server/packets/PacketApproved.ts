import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, createFieldReader } from '../utils';

interface IPacketApproved {
    keepAlive: number;
    freqKeepAlive: number;
    directSessionUpdate: number;
    privateIdleTimeout: number;
    pageMeTimeoutMessage: number;
    pttReleaseTime: number;
    pttTimeMaxAllowed: number;
    kidnapPttDisabled: number;
    maxSilence: number;
    networkSignalFloor: number;
    comSeqIdleTime: number;
    comSeqLocalIdleTime: number;
    retryTimer: number;
    numRetries: number;
    noSessionEna: number;
    maxFailedPackets: number;
    userInactivity: number;
    serverProtocolVersion: number;
    privileges: bigint;
    secondarySireIp: string;
    primarySireIp: string;
}

export class PacketApproved extends Packet {
    public parsedPacket: IPacketApproved;

    constructor(header?: PacketHeader, data?: Uint8Array, isNewHeaderNeeded?: boolean) {
        super(ECommand.ecApproved, header, data, isNewHeaderNeeded);
        this.parsedPacket = this.initializeParsedPacket();
    }

    private initializeParsedPacket(): IPacketApproved {
        return {
            keepAlive: 0,
            freqKeepAlive: 0,
            directSessionUpdate: 0,
            privateIdleTimeout: 0,
            pageMeTimeoutMessage: 0,
            pttReleaseTime: 0,
            pttTimeMaxAllowed: 0,
            kidnapPttDisabled: 0,
            maxSilence: 0,
            networkSignalFloor: 0,
            comSeqIdleTime: 0,
            comSeqLocalIdleTime: 0,
            retryTimer: 0,
            numRetries: 0,
            noSessionEna: 0,
            maxFailedPackets: 0,
            userInactivity: 0,
            serverProtocolVersion: 0,
            privileges: 0n,
            secondarySireIp: '',
            primarySireIp: '',
        };
    }

    private readIpAddress(value: number): string {
        return [
            (value >> 24) & 255,
            (value >> 16) & 255,
            (value >> 8) & 255,
            value & 255
        ].join('.');
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        const readField = createFieldReader(buffer);

        this.parsedPacket = {
            keepAlive: readField(16),
            freqKeepAlive: readField(16),
            directSessionUpdate: readField(8),
            privateIdleTimeout: readField(8),
            pageMeTimeoutMessage: readField(8),
            pttReleaseTime: readField(8),
            pttTimeMaxAllowed: readField(8),
            kidnapPttDisabled: readField(8),
            maxSilence: readField(8),
            networkSignalFloor: readField(8),
            comSeqIdleTime: readField(8),
            comSeqLocalIdleTime: readField(8),
            retryTimer: readField(8),
            numRetries: readField(3),
            noSessionEna: readField(1),
            maxFailedPackets: readField(4),
            userInactivity: readField(10),
            serverProtocolVersion: readField(32),
            privileges: BigInt(readField(64)),
            secondarySireIp: this.readIpAddress(readField(32)),
            primarySireIp: this.readIpAddress(readField(32)),
        };
    }

    toBuffer(): Buffer {
        // this packet is only sent by the server
        return Buffer.alloc(0);
    }
}