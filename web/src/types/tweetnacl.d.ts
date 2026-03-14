// projects/web/src/types/tweetnacl.d.ts
declare module "tweetnacl" {
  export interface SignKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export interface BoxKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export interface SignKeyPairFactory {
    (): SignKeyPair;
    fromSeed(seed: Uint8Array): SignKeyPair;
  }

  export interface BoxKeyPairFactory {
    (): BoxKeyPair;
    fromSecretKey(secretKey: Uint8Array): BoxKeyPair;
  }

  export interface DetachedSigner {
    (message: Uint8Array, secretKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  }

  export interface NaclSign {
    keyPair: SignKeyPairFactory;
    detached: DetachedSigner;
  }

  export interface NaclBox {
    keyPair: BoxKeyPairFactory;
  }

  export interface Nacl {
    sign: NaclSign;
    box: NaclBox;
    randomBytes(n: number): Uint8Array;
  }

  const nacl: Nacl;
  export default nacl;
}
