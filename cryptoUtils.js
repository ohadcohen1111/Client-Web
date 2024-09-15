import crypto from 'crypto';

/**
 * MD5 hash calculation helper function
 * @param {string} input - Input string to hash
 * @returns {string} MD5 hash
 */
function calcMD5(input) {
    return crypto.createHash('md5').update(input).digest('hex');
}

/**
 * Calculate the response for authorization
 * @param {string} username - Username
 * @param {string} realm - Realm
 * @param {string} password - Password
 * @param {string} method - SIP method
 * @param {string} uri - URI
 * @param {string} nonce - Nonce
 * @returns {string} Calculated response
 */
export function calcResponse(username, realm, password, method, uri, nonce) {
    const ha1 = calcMD5(`${username}:${realm}:${password}`);
    const ha2 = calcMD5(`${method}:${uri}`);
    return calcMD5(`${ha1}:${nonce}:${ha2}`);
}

/**
 * Custom Base64 encoding function
 * @param {Buffer} srcBuffer - Source buffer to encode
 * @returns {string} Base64 encoded string
 */
export function base64Encode(srcBuffer) {
    const cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const dest = [];
    let i = 0;
    while (i < srcBuffer.length) {
        const byte0 = srcBuffer[i];
        const byte1 = i + 1 < srcBuffer.length ? srcBuffer[i + 1] : 0;
        const byte2 = i + 2 < srcBuffer.length ? srcBuffer[i + 2] : 0;
        dest.push(
            cvt[byte0 & 0x3F],
            cvt[(byte0 >> 6) | ((byte1 & 0x0F) << 2)],
            i + 1 < srcBuffer.length ? cvt[(byte1 >> 4) | ((byte2 & 0x03) << 4)] : '=',
            i + 2 < srcBuffer.length ? cvt[byte2 >> 2] : '='
        );
        i += 3;
    }
    return dest.join('');
}