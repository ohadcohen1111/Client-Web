import { Packet } from './Packet';
import { PacketHeader } from './PacketHeader';
import { ECommand, readBits, writeBits } from '../utils';

enum ESessionType {
    EST_UNDEFINED = 0,
    EST_DEFAULT_SESSION = 0,
    EST_CONFERENCE = 1,
    EST_CHATROOM = 2,
    EST_ADHOC = 3,
    EST_PGROUP = 4,
    EST_PRIVATE_SERVER = 6,
    EST_PRIVATE_DIRECT = 7,
    EST_ANY = 8,
    EST_TOTAL_BROADCAST = 9,
    EST_GROUP_BROADCAST = 10,
    EST_ORGANIZATION_BROADCAST = 11,
    EST_MAX_ENTRY = EST_ORGANIZATION_BROADCAST
}

enum ESessionFlags {
    ESF_NONE = 0,
    ESF_INITIATOR_END_CALL = 0x1,
    ESF_NON_INITIATOR_LEAVE_DISABLED = 0x2,
    ESF_INITIATOR_SESSION_UPDATES_DISABLED = 0x3,
    ESF_NON_INITIATOR_SESSION_UPDATES_DISABLED = 0x4,
    ESF_NON_INITIATOR_PTT_DISABLED = 0x5,
    ESF_RFU5 = 0x6,
    ESF_RFU6 = 0x7,
    ESF_RFU7 = 0x8,
    ESF_MAX_VAL = ESF_RFU7
}

enum ESessionFlagsMask {
    ESFM_NONE = 0,
    ESFM_INITIATOR_END_CALL = 0x1,
    ESFM_NON_INITIATOR_LEAVE_DISABLED = 0x2,
    ESFM_INITIATOR_SESSION_UPDATES_DISABLED = 0x4,
    ESFM_NON_INITIATOR_SESSION_UPDATES_DISABLED = 0x8,
    ESFM_NON_INITIATOR_PTT_DISABLED = 0x10,
    ESFM_RFU5 = 0x20,
    ESFM_RFU6 = 0x40,
    ESFM_RFU7 = 0x80,
    ESFM_DEFAULT = ESFM_NONE,
    ESFM_MAX_VAL = 0x7F
}

enum ESessionPriority {
    espUndefined = 0,
    espLow = 0x0001,
    espNormal = 0x0002,
    espHigh = 0x0003,
    espUrgent = 0x0004,
    espEmergency = 0x0005
}

enum EAudioOutputDevice_t {
    AOD_CURRENT = 0,
    AOD_DEFAULT,
    AOD_HEADSET,
    AOD_SPEAKER,
    AOD_HANDS_FREE,
    AOD_BLUETOOTH,
    AOD_PASSENGERS,
    AOD_DRIVER = AOD_DEFAULT,
    AOD_EXTERNAL_SPEAKER = AOD_SPEAKER
}

enum EVocoder {
    EV_NONE = 0x00000000,
    EV_CODEC_EVRC = 0x00000001,
    EV_CODEC_AMR475 = 0x00000002,
    EV_CODEC_GSM = 0x00000004,
    EV_CODEC_SPIRIT2400 = 0x00000008,
    EV_CODEC_LPC = 0x00000010,
    EV_CODEC_GSM_HR = 0x00000020,
    EV_CODEC_PCM = 0x00000040,
    EV_CODEC_RFU8 = 0x00000080,
    EV_CODEC_RFU9 = 0x00000100,
    EV_CODEC_RFU10 = 0x00000200,
    EV_CODEC_RFU11 = 0x00000400,
    EV_CODEC_RFU12 = 0x00000800,
    EV_CODEC_RFU13 = 0x00001000,
    EV_CODEC_RFU14 = 0x00002000,
    EV_CODEC_RFU15 = 0x00004000,
    EV_CODEC_RFU16 = 0x00008000,
    EV_CODEC_ALL = 0x0000FFFF
}

export class PacketNewSession extends Packet {
    public sessionId: bigint = 0n;
    private ctlIpAddr: number = 0;
    private ctlPort: number = 0;
    private audioIpAddr: number = 0;
    private audioPort: number = 0;
    private isInitiator: boolean = false;
    private isPttEnabled: boolean = false;
    private isPublic: boolean = false;
    private isChatRoom: boolean = false;
    private isBroadcast: boolean = false;
    private isDirect: boolean = false;
    private isAdHoc: boolean = false;
    private vocoder: EVocoder = EVocoder.EV_NONE;
    private earlyMedia: boolean = false;
    private sessionFlags: ESessionFlagsMask = ESessionFlagsMask.ESFM_NONE;
    private initiatorId: bigint = 0n;
    private priority: ESessionPriority = ESessionPriority.espUndefined;
    private audioOutputDevice: EAudioOutputDevice_t = EAudioOutputDevice_t.AOD_CURRENT;

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean) {
        super(ECommand.ecNewSession, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const buffer = Buffer.from(this.data);
        let bitOffset = 0;

        this.sessionId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;
        // Skip server id (64 bits)
        bitOffset += 64;
        this.ctlIpAddr = readBits(buffer, bitOffset, 32);
        bitOffset += 32;
        this.ctlPort = readBits(buffer, bitOffset, 16);
        bitOffset += 16;
        this.audioIpAddr = readBits(buffer, bitOffset, 32);
        bitOffset += 32;
        this.audioPort = readBits(buffer, bitOffset, 16);
        bitOffset += 16;
        this.isInitiator = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.isPttEnabled = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.isPublic = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.isChatRoom = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.isDirect = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.isAdHoc = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        this.vocoder = readBits(buffer, bitOffset, 16);
        bitOffset += 16;
        this.earlyMedia = Boolean(readBits(buffer, bitOffset, 1));
        bitOffset += 1;
        // Skip RFU1 (1 bit)
        bitOffset += 1;
        this.sessionFlags = readBits(buffer, bitOffset, 8);
        bitOffset += 8;
        this.initiatorId = this.readBigIntFromBuffer(buffer, bitOffset, 64);
        bitOffset += 64;
        this.priority = readBits(buffer, bitOffset, 8);
        bitOffset += 8;
        this.audioOutputDevice = readBits(buffer, bitOffset, 8);
        bitOffset += 8;
        // Skip RFU2 (8 bits) and RFU3 (16 bits)
        bitOffset += 24;
        this.isBroadcast = Boolean(readBits(buffer, bitOffset, 1));
    }



    toBuffer(): Buffer {
        const body = Buffer.alloc(28);  // 217 bits = 28 bytes (rounded up)
        let state = { offset: 0, bitOffset: 0 };

        writeBits(body, this.sessionId, 64, state);
        writeBits(body, 0n, 64, state);  // server id (64 bits of 0)
        writeBits(body, this.ctlIpAddr, 32, state);
        writeBits(body, this.ctlPort, 16, state);
        writeBits(body, this.audioIpAddr, 32, state);
        writeBits(body, this.audioPort, 16, state);
        writeBits(body, this.isInitiator ? 1 : 0, 1, state);
        writeBits(body, this.isPttEnabled ? 1 : 0, 1, state);
        writeBits(body, this.isPublic ? 1 : 0, 1, state);
        writeBits(body, this.isChatRoom ? 1 : 0, 1, state);
        writeBits(body, this.isDirect ? 1 : 0, 1, state);
        writeBits(body, this.isAdHoc ? 1 : 0, 1, state);
        writeBits(body, this.vocoder, 16, state);
        writeBits(body, this.earlyMedia ? 1 : 0, 1, state);
        writeBits(body, 0, 1, state);  // RFU1 (1 bit of 0)
        writeBits(body, this.sessionFlags, 8, state);
        writeBits(body, this.initiatorId, 64, state);
        writeBits(body, this.priority, 8, state);
        writeBits(body, this.audioOutputDevice, 8, state);
        writeBits(body, 0, 24, state);  // RFU2 (8 bits) and RFU3 (16 bits)
        writeBits(body, this.isBroadcast ? 1 : 0, 1, state);

        return Buffer.concat([this.header.toBuffer(), body]);
    }

    // Getter and setter methods for all fields...

    getType(): ESessionType {
        if (this.isPublic) {
            if (this.isDirect) {
                return ESessionType.EST_UNDEFINED;
            } else {
                if (this.isAdHoc) {
                    if (this.isChatRoom) {
                        return ESessionType.EST_UNDEFINED;
                    } else {
                        return ESessionType.EST_ADHOC;
                    }
                } else {
                    if (this.isChatRoom) {
                        return ESessionType.EST_CHATROOM;
                    } else {
                        if (this.isBroadcast) {
                            return ESessionType.EST_ORGANIZATION_BROADCAST;
                        } else {
                            return ESessionType.EST_CONFERENCE;
                        }
                    }
                }
            }
        } else {
            if (this.isAdHoc || this.isChatRoom) {
                return ESessionType.EST_UNDEFINED;
            } else {
                if (this.isDirect) {
                    return ESessionType.EST_PRIVATE_DIRECT;
                } else {
                    return ESessionType.EST_PRIVATE_SERVER;
                }
            }
        }
    }

    printInfo(): void {
        console.log("New Session Packet:");
        console.log(`Session ID: ${this.sessionId}`);
        console.log(`Control IP: ${this.ctlIpAddr}, Port: ${this.ctlPort}`);
        console.log(`Audio IP: ${this.audioIpAddr}, Port: ${this.audioPort}`);
        console.log(`Is Initiator: ${this.isInitiator}`);
        console.log(`Is PTT Enabled: ${this.isPttEnabled}`);
        console.log(`Is Public: ${this.isPublic}`);
        console.log(`Is Chat Room: ${this.isChatRoom}`);
        console.log(`Is Broadcast: ${this.isBroadcast}`);
        console.log(`Is Direct: ${this.isDirect}`);
        console.log(`Is Ad Hoc: ${this.isAdHoc}`);
        console.log(`Vocoder: ${EVocoder[this.vocoder]}`);
        console.log(`Early Media: ${this.earlyMedia}`);
        console.log(`Session Flags: ${ESessionFlagsMask[this.sessionFlags]}`);
        console.log(`Initiator ID: ${this.initiatorId}`);
        console.log(`Priority: ${ESessionPriority[this.priority]}`);
        console.log(`Audio Output Device: ${EAudioOutputDevice_t[this.audioOutputDevice]}`);
        console.log(`Session Type: ${ESessionType[this.getType()]}`);
    }

    private readBigIntFromBuffer(buffer: Buffer, startBit: number, numBits: number): bigint {
        let value = BigInt(0);
        for (let i = 0; i < numBits; i++) {
            const byteIndex = Math.floor((startBit + i) / 8);
            const bitIndex = (startBit + i) % 8;
            const bit = (buffer[byteIndex] & (1 << (7 - bitIndex))) !== 0;
            value = (value << BigInt(1)) | BigInt(bit ? 1 : 0);
        }
        return value;
    }
}