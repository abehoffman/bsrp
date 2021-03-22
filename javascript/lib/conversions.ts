import { BigInteger } from "jsbn";

export const bigIntegerToBigEndianBytes = (bi: BigInteger): Uint8Array => {
  const shifts = Math.floor((bi.bitLength() + 7) / 8);
  const andBigInteger = new BigInteger("FF", 16);
  const byteArray = new Uint8Array(shifts);

  for (let i = 0; i < shifts; i++) {
    byteArray[i] = bi.and(andBigInteger).intValue();
    bi = bi.shiftRight(8);
  }

  // We want to store in big endian order
  return byteArray.reverse();
};

export const bigEndianBytesToBigInteger = (byteArray: Uint8Array): BigInteger => {
  const multShift = new BigInteger("256", 10);

  let bi = new BigInteger(byteArray[0].toString(16), 16);

  for (let i = 1; i < byteArray.byteLength; i++) {
    const nextByte = new BigInteger(byteArray[i].toString(16), 16);
    bi = bi.multiply(multShift).add(nextByte);
  }

  return bi;
};
