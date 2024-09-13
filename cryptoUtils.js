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