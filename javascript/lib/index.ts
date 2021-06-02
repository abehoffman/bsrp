import { BigInteger } from "jsbn";

import {
  generateRandomBytes,
  hash,
  toBigInteger,
  pad,
  calculateM,
  calculateX,
} from "./utils";
import { generator, prime } from "./constants";

export { toBigInteger };

export interface APair {
  ephemeralA: BigInteger;
  publicA: BigInteger;
}

export const generateAPair = (): APair => {
  const ephemeralA = toBigInteger(generateRandomBytes(32));
  const publicA = generator.modPow(ephemeralA, prime);
  return {
    ephemeralA: ephemeralA,
    publicA: publicA,
  };
};

export interface ProcessedChallenge {
  message: BigInteger;
  sessionKey: BigInteger;
}

export const processChallenge = async (
  identity: string,
  password: string,
  salt: BigInteger,
  ephemeralA: BigInteger,
  publicA: BigInteger,
  publicB: BigInteger
): Promise<null | ProcessedChallenge> => {
  const width = Math.floor((prime.bitLength() + 7) / 8);

  const paddedGenerator = pad(generator, width);
  const paddedPublicA = pad(publicA, width);
  const paddedPublicB = pad(publicB, width);

  // RFC 5054 u
  const scrambler = toBigInteger(await hash(paddedPublicA, paddedPublicB));

  const x = await calculateX(salt, identity, password);
  // RFC 5054 k
  const multiplier = toBigInteger(await hash(prime, paddedGenerator));

  // SRP-6a safety checks
  if (publicB.mod(prime).equals(BigInteger.ZERO)) {
    return null;
  }

  if (scrambler.equals(BigInteger.ZERO)) {
    return null;
  }

  // Premaster secret, S = t1: (B - k*(generator^x)) ^ t2: (a + u*x)
  const t1 = publicB.subtract(multiplier.multiply(generator.modPow(x, prime)));
  const t2 = ephemeralA.add(scrambler.multiply(x));

  // Calculate shared session key
  const S = t1.modPow(t2, prime);
  const sessionKey = await hash(S);

  const message = await calculateM(
    generator,
    prime,
    identity,
    salt,
    publicA,
    publicB,
    sessionKey
  );

  return {
    message: toBigInteger(message),
    sessionKey: toBigInteger(sessionKey),
  };
};

export const verifySession = async (
  publicA: BigInteger,
  message: BigInteger,
  sessionKey: BigInteger,
  serverHAMK: BigInteger
): Promise<BigInteger | null> => {
  const clientHAMK = await hash(publicA, message, sessionKey);

  if (!toBigInteger(clientHAMK).equals(serverHAMK)) {
    return null;
  }

  return toBigInteger(clientHAMK);
};
