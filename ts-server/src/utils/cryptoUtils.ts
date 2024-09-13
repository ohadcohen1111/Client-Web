import crypto from 'crypto';

export function calcMD5(input: string): string {
  return crypto.createHash('md5').update(input).digest('hex');
}

export function calcResponse(
  username: string,
  realm: string,
  password: string,
  method: string,
  uri: string,
  nonce: string
): string {
  const ha1 = calcMD5(`${username}:${realm}:${password}`);
  const ha2 = calcMD5(`${method}:${uri}`);
  return calcMD5(`${ha1}:${nonce}:${ha2}`);
}
