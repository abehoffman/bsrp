import { Sha256 } from "@aws-crypto/sha256-browser";
import { BigInteger } from "jsbn";

import {
  bigEndianBytesToBigInteger,
  bigIntegerToBigEndianBytes,
} from "./conversions";

export const generateRandomBytes = (length: number): Uint8Array => {
  const buffer = new Uint8Array(length);
  const randomBytes = crypto.getRandomValues(buffer);

  return randomBytes;
};

export type Input = BigInteger | Uint8Array;

export const toBytes = (input: Input): Uint8Array => {
  if (input instanceof BigInteger) {
    return bigIntegerToBigEndianBytes(input);
  } else {
    return input;
  }
};

export const toBigInteger = (input: Input): BigInteger => {
  if (input instanceof Uint8Array) {
    return bigEndianBytesToBigInteger(input);
  } else {
    return input;
  }
};

export const pad = (input: Input, length: number): Uint8Array => {
  const unpadded = toBytes(input);
  const padding = new Uint8Array(length - unpadded.byteLength);

  const paddedUint8Array = new Uint8Array(length);

  paddedUint8Array.set(padding);
  paddedUint8Array.set(unpadded, padding.byteLength);

  return paddedUint8Array;
};

export type HashInput = Input | string;

export const hash = async (...args: Array<HashInput>): Promise<Uint8Array> => {
  const hash = new Sha256();

  args.forEach((arg: HashInput) => {
    if (typeof arg === "string") {
      hash.update(arg, "utf8");
    } else {
      hash.update(toBytes(arg));
    }
  });

  const digestHash = await hash.digest();

  return digestHash;
};

export const calculateX = async (
  salt: BigInteger,
  identity: string,
  password: string
): Promise<BigInteger> => {
  const preSalt = await hash(identity, ":", password);
  const postSalt = await hash(salt, preSalt);

  return toBigInteger(postSalt);
};

export const calculateM = async (
  generator: BigInteger,
  prime: BigInteger,
  identity: string,
  salt: BigInteger,
  A: BigInteger,
  B: BigInteger,
  sessionKey: Uint8Array
): Promise<Uint8Array> => {
  const hashGenerator = await hash(generator);
  const hashPrime = await hash(prime);
  const hashIdentity = await hash(identity);

  const xorGeneratorPrime = toBigInteger(hashGenerator).xor(
    toBigInteger(hashPrime)
  );

  return hash(xorGeneratorPrime, hashIdentity, salt, A, B, sessionKey);
};
