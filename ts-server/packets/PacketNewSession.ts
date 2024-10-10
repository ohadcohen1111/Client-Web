import { Packet } from './Packet';
import { Parser } from 'binary-parser';
import { PacketHeader } from './PacketHeader';
import { ECommand } from '../utils';

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
    public initiatorId: bigint = 0n;
    public ctlIpAddr: number = 0;
    public ctlPort: number = 0;
    public audioIpAddr: number = 0;
    public audioPort: number = 0;
    public vocoder: EVocoder = EVocoder.EV_NONE;
    public sessionFlags: ESessionFlagsMask = ESessionFlagsMask.ESFM_NONE;
    public priority: ESessionPriority = ESessionPriority.espUndefined;
    public audioOutputDevice: EAudioOutputDevice_t = EAudioOutputDevice_t.AOD_CURRENT;
    public isInitiator: boolean = false;
    public isPttEnabled: boolean = false;
    public isPublic: boolean = false;
    public isChatRoom: boolean = false;
    public isBroadcast: boolean = false;
    public isDirect: boolean = false;
    public isAdHoc: boolean = false;
    public earlyMedia: boolean = false;

    private static parser = new Parser()
        .endianess('big')
        .uint64('sessionId')
        .skip(8) // Skip server id (64 bits = 8 bytes)
        .bit32('ctlIpAddr')
        .bit16('ctlPort')
        .bit32('audioIpAddr')
        .bit16('audioPort')
        .bit1('isInitiator')
        .bit1('isPttEnabled')
        .bit1('isPublic')
        .bit1('isChatRoom')
        .bit1('isDirect')
        .bit1('isAdHoc')
        .bit16('vocoder')
        .bit1('earlyMedia')
        .bit1('rfu1') // Skip RFU1 (1 bit)
        .bit8('sessionFlags')
        .uint64('initiatorId')
        .bit8('priority')
        .bit8('audioOutputDevice')
        .skip(3) // Skip RFU2 (8 bits) and RFU3 (16 bits) = 3 bytes
        .bit1('isBroadcast')
        .bit7('padding'); // Align to byte boundary

    constructor(header: PacketHeader, data: Uint8Array, isNewHeaderNeeded: boolean) {
        super(ECommand.ecNewSession, header, data, isNewHeaderNeeded);
    }

    parseData(): void {
        if (!this.data) {
            throw new Error("No data to parse");
        }

        const parsed = PacketNewSession.parser.parse(this.data);

        this.sessionId = BigInt(parsed.sessionId);
        this.ctlIpAddr = parsed.ctlIpAddr;
        this.ctlPort = parsed.ctlPort;
        this.audioIpAddr = parsed.audioIpAddr;
        this.audioPort = parsed.audioPort;
        this.isInitiator = parsed.isInitiator === 1;
        this.isPttEnabled = parsed.isPttEnabled === 1;
        this.isPublic = parsed.isPublic === 1;
        this.isChatRoom = parsed.isChatRoom === 1;
        this.isDirect = parsed.isDirect === 1;
        this.isAdHoc = parsed.isAdHoc === 1;
        this.vocoder = parsed.vocoder;
        this.earlyMedia = parsed.earlyMedia === 1;
        this.sessionFlags = parsed.sessionFlags;
        this.initiatorId = BigInt(parsed.initiatorId);
        this.priority = parsed.priority;
        this.audioOutputDevice = parsed.audioOutputDevice;
        this.isBroadcast = parsed.isBroadcast === 1;
    }

    toBuffer(): Buffer {
        const buffer = Buffer.alloc(28); // 217 bits rounded up to nearest byte
        let offset = 0;

        buffer.writeBigUInt64BE(this.sessionId, offset);
        offset += 8;
        buffer.writeBigUInt64BE(0n, offset); // server id
        offset += 8;
        buffer.writeUInt32BE(this.ctlIpAddr, offset);
        offset += 4;
        buffer.writeUInt16BE(this.ctlPort, offset);
        offset += 2;
        buffer.writeUInt32BE(this.audioIpAddr, offset);
        offset += 4;
        buffer.writeUInt16BE(this.audioPort, offset);
        offset += 2;

        const flagsByte =
            (this.isInitiator ? 0x80 : 0) |
            (this.isPttEnabled ? 0x40 : 0) |
            (this.isPublic ? 0x20 : 0) |
            (this.isChatRoom ? 0x10 : 0) |
            (this.isDirect ? 0x08 : 0) |
            (this.isAdHoc ? 0x04 : 0);
        buffer.writeUInt8(flagsByte, offset);
        offset += 1;

        buffer.writeUInt16BE(this.vocoder, offset);
        offset += 2;

        const miscByte =
            (this.earlyMedia ? 0x80 : 0) |
            (this.isBroadcast ? 0x01 : 0);
        buffer.writeUInt8(miscByte, offset);
        offset += 1;

        buffer.writeUInt8(this.sessionFlags, offset);
        offset += 1;
        buffer.writeBigUInt64BE(this.initiatorId, offset);
        offset += 8;
        buffer.writeUInt8(this.priority, offset);
        offset += 1;
        buffer.writeUInt8(this.audioOutputDevice, offset);
        // The last 3 bytes are left as zeros (RFU2, RFU3, and padding)

        return Buffer.concat([this.header.toBuffer(), buffer]);
    }

    getType(): ESessionType {
        if (this.isPublic) {
            if (this.isDirect) return ESessionType.EST_UNDEFINED;
            if (this.isAdHoc) return this.isChatRoom ? ESessionType.EST_UNDEFINED : ESessionType.EST_ADHOC;
            if (this.isChatRoom) return ESessionType.EST_CHATROOM;
            return this.isBroadcast ? ESessionType.EST_ORGANIZATION_BROADCAST : ESessionType.EST_CONFERENCE;
        }
        if (this.isAdHoc || this.isChatRoom) return ESessionType.EST_UNDEFINED;
        return this.isDirect ? ESessionType.EST_PRIVATE_DIRECT : ESessionType.EST_PRIVATE_SERVER;
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
}