export function writeBits(buffer: Buffer, value: number, bits: number, offset: number, bitOffset: number) {
    while (bits > 0) {
      const availableBits = 8 - (bitOffset % 8);
      const bitsToWrite = Math.min(availableBits, bits);
      const mask = (1 << bitsToWrite) - 1;
      const shiftedValue = (value & mask) << (availableBits - bitsToWrite);
      buffer[offset] |= shiftedValue;
      value >>= bitsToWrite;
      bits -= bitsToWrite;
      bitOffset += bitsToWrite;
      if (bitOffset % 8 === 0) {
        offset++;
      }
    }
  }
  
  export function writeString(buffer: Buffer, str: string, maxBytes: number, offset: number): void {
    const buf = Buffer.from(str, 'utf8');
    buf.copy(buffer, offset, 0, Math.min(buf.length, maxBytes));
    offset += maxBytes;
  }
  