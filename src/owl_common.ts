import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bytesToNumberBE, concatBytes, numberToVarBytesBE } from "@noble/curves/abstract/utils";

export type Point = ProjPointType<bigint>

export interface ZKP {
    V: Point;
    r: bigint;
}

export class ZKPVerificationFailure extends Error {
    constructor() {
      super("ZKP verification failed");
      this.name = "ZKPVerificationFailure";
    }
}

export enum Curves {
    P256 = 256,
    P384 = 384,
    P521 = 521
}

export interface Config {
    curve: Curves;
    serverId: string;
} 

export abstract class OwlCommon {
    serverId: string;
    n: bigint;
    G: Point;
    constructor(config: Config) {
        const { curve, serverId } = config;
        const c = {
            [Curves.P256]: p256,
            [Curves.P384]: p384,
            [Curves.P521]: p521
        }[curve];
        [this.serverId, this.n, this.G] = [
            serverId,
            c.CURVE.n,
            new c.ProjectivePoint(c.CURVE.Gx, c.CURVE.Gy, 1n),
        ]
    }
    /**
     * Generate a cryptographically secure random number 
     * between from and to inclusive
     * @param from Lower limit
     * @param to Upper limit
     * @returns Random number
     */
    rand(from: bigint, to: bigint): bigint {
        const range = to - from;
        // convert range to binary, divide by 8 for number of bytes
        const bytesNeeded = Math.ceil(range.toString(2).length / 8);
        // fill an array the size of bytesNeeded with cryptographically secure random numbers
        const randBytes = crypto.getRandomValues(new Uint8Array(bytesNeeded));
        // convert to bigint
        const randVal = bytesToNumberBE(randBytes);
        // modulo randVal to get value in range [0, range]
        // then add from to get value in range [from, to]
        return from + randVal % (range + 1n);
    }
    /**
     * Concatenate the given numbers and strings into one string
     * @param args Any number of BigNumber or string objects
     * @returns Concatenated objects
     */
    concat(...args: Array<bigint | string | Point>): Uint8Array {
        return concatBytes(...args.map(arg => {
            if(typeof arg == "bigint"){
                return numberToVarBytesBE(arg)
            } else if(typeof arg == "string"){
                return new TextEncoder().encode(arg)
            } else if(arg.toRawBytes){
                return arg.toRawBytes();
            } else{
                throw new Error("Unsupported type in concat");
            }
        }));
    }
    /**
     * Hash a Uint8Array, string or bigint to a bigint
     * @param x Value to be hashed
     * @returns Hash output as bigint
     */
    async H(x: Uint8Array | string | bigint): Promise<bigint> {
        if(typeof x == "string"){
            x = new TextEncoder().encode(x);
        } else if(typeof x == "bigint"){
            x = numberToVarBytesBE(x);
        }
        const hashBuffer = await crypto.subtle.digest("SHA-256", x); // hash the message
        return bytesToNumberBE(new Uint8Array(hashBuffer));
    }
    /**
     * Create a Schnorr Non-Interactive Zero Knowledge Proof (NIZKP)
     * from the given private key, generator, public key and
     * prover identity
     * @param x Private key
     * @param G Generator
     * @param X Public key
     * @param prover Prover identity
     * @returns Zero knowledge proof
     */
    async createZKP(x: bigint, G: Point, X: Point, prover: string): Promise<ZKP> {
        const v = this.rand(1n, this.n - 1n);
        const V = G.multiply(v);
        const h = await this.H(this.concat(G, V, X, prover));
        const r = (v - (x * h)) % this.n;
        return {V, r};
    }
    /**
     * Verify the given ZKP for the given generator, public key
     * and prover identity
     * @param zkp ZKP to verify
     * @param G Generator
     * @param X Public key
     * @param prover Prover identity
     */
    async verifyZKP(zkp: ZKP, G: Point, X: Point, prover: string): Promise<boolean> {
        const {V, r} = zkp;
        const h = await this.H(this.concat(G, V, X, prover));
        // check X is valid
        try{
            X.assertValidity();
        } catch { return false; }
        // check V = G*r + X*h
        return V.equals(G.multiply(r).add(X.multiply(h % this.n)));
    }
}