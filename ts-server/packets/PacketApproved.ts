import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, createFieldReader } from '../utils';

interface CPacketApproved {
    KEEP_ALIVE: number;
    FREQ_KEEP_ALIVE: number;
    DIRECT_SESSION_UPDATE: number;
    PRIVATE_IDLE_TIMEOUT: number;
    PAGE_ME_TIMEOUT_MESSAGE: number;
    PTT_RELEASE_TIME: number;
    PTT_TIME_MAX_ALLOWED: number;
    KIDNAP_PTT_DISABLED: number;
    MAX_SILENCE: number;
    NETWORK_SIGNAL_FLOOR: number;
    COM_SEQ_IDLE_TIME: number;
    COM_SEQ_LOCAL_IDLE_TIME: number;
    RETRY_TIMER: number;
    NUM_RETRIES: number;
    NO_SESSION_ENA: number;
    MAX_FAILED_PACKETS: number;
    USER_INACTIVITY: number;
    SERVER_PROTOCOL_VERSION: number;
    PRIVILEGES: bigint;
    SECONDARY_SIRE_IP: string;
    PRIMARY_SIRE_IP: string;
}

export class PacketApproved extends Packet {
    private parsedPacket: CPacketApproved;

    constructor(header?: PacketHeader, data?: Uint8Array) {
        super(ECommand.ecApproved, header, data);
        this.parsedPacket = this.initializeParsedPacket();
    }

    private initializeParsedPacket(): CPacketApproved {
        return {
            KEEP_ALIVE: 0,
            FREQ_KEEP_ALIVE: 0,
            DIRECT_SESSION_UPDATE: 0,
            PRIVATE_IDLE_TIMEOUT: 0,
            PAGE_ME_TIMEOUT_MESSAGE: 0,
            PTT_RELEASE_TIME: 0,
            PTT_TIME_MAX_ALLOWED: 0,
            KIDNAP_PTT_DISABLED: 0,
            MAX_SILENCE: 0,
            NETWORK_SIGNAL_FLOOR: 0,
            COM_SEQ_IDLE_TIME: 0,
            COM_SEQ_LOCAL_IDLE_TIME: 0,
            RETRY_TIMER: 0,
            NUM_RETRIES: 0,
            NO_SESSION_ENA: 0,
            MAX_FAILED_PACKETS: 0,
            USER_INACTIVITY: 0,
            SERVER_PROTOCOL_VERSION: 0,
            PRIVILEGES: 0n,
            SECONDARY_SIRE_IP: '',
            PRIMARY_SIRE_IP: '',
        };
    }

    private readIPAddress(value: number): string {
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
            KEEP_ALIVE: readField(16),
            FREQ_KEEP_ALIVE: readField(16),
            DIRECT_SESSION_UPDATE: readField(8),
            PRIVATE_IDLE_TIMEOUT: readField(8),
            PAGE_ME_TIMEOUT_MESSAGE: readField(8),
            PTT_RELEASE_TIME: readField(8),
            PTT_TIME_MAX_ALLOWED: readField(8),
            KIDNAP_PTT_DISABLED: readField(8),
            MAX_SILENCE: readField(8),
            NETWORK_SIGNAL_FLOOR: readField(8),
            COM_SEQ_IDLE_TIME: readField(8),
            COM_SEQ_LOCAL_IDLE_TIME: readField(8),
            RETRY_TIMER: readField(8),
            NUM_RETRIES: readField(3),
            NO_SESSION_ENA: readField(1),
            MAX_FAILED_PACKETS: readField(4),
            USER_INACTIVITY: readField(10),
            SERVER_PROTOCOL_VERSION: readField(32),
            PRIVILEGES: BigInt(readField(64)),
            SECONDARY_SIRE_IP: this.readIPAddress(readField(32)),
            PRIMARY_SIRE_IP: this.readIPAddress(readField(32)),
        };
    }

    toBuffer(): Buffer {
        // this packet is only sent by the server
        return Buffer.alloc(0);
    }
}