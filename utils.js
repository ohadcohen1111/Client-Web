/**
 * Generic function to write a value into a buffer at a specific bit position
 * @param {Buffer} buffer - The buffer to write into
 * @param {number | bigint} value - The value to write (can be number or BigInt)
 * @param {number} bitOffset - The bit position to start writing
 * @param {number} numBits - The number of bits to write
 */
export function writeBits(body, value, bits, state) {
    let { bitOffset, offset } = state;
    let isBigInt = typeof value === 'bigint';

    while (bits > 0) {
        const availableBits = 8 - (bitOffset % 8);
        const bitsToWrite = Math.min(availableBits, bits);
        const mask = (1n << BigInt(bitsToWrite)) - 1n;

        // Shift based on whether the value is BigInt or Number
        const shiftedValue = isBigInt
            ? (value >> BigInt(bits - bitsToWrite)) & mask
            : (value >> (bits - bitsToWrite)) & Number(mask);

        // Write the shifted value to the buffer
        body[offset] |= Number(shiftedValue) << (availableBits - bitsToWrite);

        bitOffset += bitsToWrite;
        bits -= bitsToWrite;

        if (bitOffset % 8 === 0) {
            offset++;
        }
    }

    // Update the state with new values of offset and bitOffset
    state.bitOffset = bitOffset;
    state.offset = offset;
}

export function getSIPMethod(cmd) {
    switch (cmd) {
        case 1: // ecAck
        case 3: // ecAccept
        case 4: // ecReject
            return "ACK";
        case 38: // ecAuthorize
        case 39: // ecReRegister
            return "FORBIDDEN";
        case 5: // ecRegister
        case 6: // ecUnregister
        case 7: // ecKeepAlive
            return "REGISTER";
        case 7: // ecApproved
            return "APPROVED";
        case 8: // ecPocUriAction
        case 9: // ecCreateAdHoc
        case 10: // ecCreateAdHocEx
        case 11: // ecRedirectJoin
        case 12: // ecJoinEx
        case 13: // ecJoin
        case 14: // ecPending
        case 15: // ecNewSession
            return "INVITE";
        case 16: // ecLeave
        case 17: // ecEndSession
            return "BYE";
        case 21: // ecPABSyncRequest
        case 22: // ecSubscribe
            return "SUBSCRIBE";
        case 23: // ecEnablePTT
        case 24: // ecDisablePTT
        case 25: // ecControlPTT
        case 26: // ecForward
        case 27: // ecPABGroupList
        case 28: // ecPABContactList
        case 29: // ecPABGroupIDList
        case 30: // ecPABStateList
            return "NOTIFY";
        case 31: // ecPABSearch
        case 32: // ecPABSearchOrg
        case 33: // ecPABSearchResults
        case 34: // ecPABSearchOrgResults
        case 35: // ecPABSessionUpdatesList
        case 36: // ecDirSesLog
            return "INFO";
        default:
            return "ERROR";
    }
}

export const ECommand = Object.freeze({
    /*general*/
    ecNull: 0,
    ecAck: 1,
    ecReRegister: 2,
    ecServerBusy: 3,
    ecKeepAlive: 4,
    /*registration*/
    ecRegister: 5,
    ecUnregister: 6,
    ecApproved: 7,
    ecDenied: 8,
    /*session*/
    ecJoin: 9,
    ecCreateAdHoc: 10,
    ecLeave: 11,
    ecNewSession: 12,
    ecEndSession: 13,
    ecEnablePTT: 14,
    ecDisablePTT: 15,
    ecAccept: 16,
    ecReject: 17,
    ecPending: 18,
    ecError: 19,
    ecDirSesLog: 20,
    /*PAB*/
    ecPABSyncRequest: 21,
    ecPABGroupList: 22,
    ecPABContactList: 23,
    ecPABGroupIDList: 24,
    ecPABStateList: 25,
    ecPABSessionUpdatesList: 26,
    ecPABSearch: 27,
    ecPABSearchResults: 28,
    ecRedirectJoin: 29,
    ecRemoteUpdateContact: 30,
    ecPABSearchOrg: 31,
    ecPABSearchOrgResults: 32,
    ecForward: 35,
    ecJoinEx: 36,
    ecPocUriAction: 37,
    ecAuthorize: 38,
    ecSosAction: 39,
    ecFloorGranted: 40,
    ecPABSubscribe: 41,
    ecPABUnsubscribe: 42,
    ecRemoteActions: 43,
    ecAddToSession: 44,
    ecSessionRefresh: 45,
    ecOpenChannel: 46,
    ecCreateAdHocEx: 47,
    ecPublish: 48,
    ecControlPTT: 49,
    ecSubscribe: 50,
    ecSessionInfo: 51,
    ecGroupSessionInfo: 55,
    ecServiceDiscovery: 56,
    ecDispatcherRequest: 57,
    ecUserLog: 58,
    ecGroupInChargeSiteUpdate: 59,
    ecSiteBackOnline: 60,
    ecUpgradeVersion: 61,
    ecPABReachMeList: 62,
    ecPlaceSavedForReachMe: 63,
    ecNack: 64,
    ecMoveSiteByOrg: 69,
    ecReachMeGroup: 70,
    ecChangeCallInitiator: 71,
    ecGroupAction: 72,
    ecSiteList: 73,
    ecPABRequest: 74,
    ecAuthLongToken: 75,
    ecPasswordDenied: 76,
    ecGroupOneToOneSession: 77,
    ecRecorderStatistic: 78,
    ecPABGroupListEx: 79,
    ecLast: 76 // Adjust according to the highest command
});