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