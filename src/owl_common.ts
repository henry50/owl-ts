import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import {
    bytesToHex,
    bytesToNumberBE,
    concatBytes,
    numberToVarBytesBE,
} from "@noble/curves/abstract/utils";

export type Point = ProjPointType<bigint>;

export interface ZKP {
    h: bigint;
    r: bigint;
}

export class ZKPVerificationFailure extends Error {
    constructor() {
        super("ZKP verification failed");
        this.name = "ZKPVerificationFailure";
    }
}

export class AuthenticationFailure extends Error {
    constructor() {
        super("Authentication failed");
        this.name = "AuthenticationFailure";
    }
}

export enum Curves {
    P256 = 256,
    P384 = 384,
    P521 = 521,
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
            [Curves.P521]: p521,
        }[curve];
        [this.serverId, this.n, this.G] = [
            serverId,
            c.CURVE.n,
            new c.ProjectivePoint(c.CURVE.Gx, c.CURVE.Gy, 1n),
        ];
    }
    /**
     * Modulo formula from https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Remainder
     * @param x Dividend
     * @returns x mod n
     */
    modN(x: bigint) {
        return ((x % this.n) + this.n) % this.n;
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
        return from + (randVal % (range + 1n));
    }
    /**
     * Concatenate any number of Uint8Array, string, bigint or Point to a single Uint8Array
     * @param args Items to concatenate
     * @returns Uint8Array
     */
    concatToBytes(
        ...args: Array<Uint8Array | string | bigint | Point>
    ): Uint8Array {
        return concatBytes(
            ...args.map((arg) => {
                if (arg instanceof Uint8Array) {
                    return arg;
                } else if (typeof arg == "string") {
                    return new TextEncoder().encode(arg);
                } else if (typeof arg == "bigint") {
                    return numberToVarBytesBE(arg);
                } else if (arg.toRawBytes) {
                    // Point
                    return arg.toRawBytes();
                } else {
                    throw new Error("Unsupported type in concatToBytes");
                }
            }),
        );
    }
    /**
     * Hash any number of Uint8Array, string, bigint or Point to a bigint
     * @param args Items to hash
     * @returns Hash output as bigint
     */
    async H(
        ...args: Array<Uint8Array | string | bigint | Point>
    ): Promise<bigint> {
        // convert each acceptable input type to Uint8Array and concatenate
        const bytes = this.concatToBytes(...args);
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        return bytesToNumberBE(new Uint8Array(hashBuffer));
    }
    /**
     * Derive HMAC for key confirmation
     * @param kcKey Key confirmation key
     * @param senderId Sender identity
     * @param receiverId Receiver identity
     * @param sender1 First sender value
     * @param sender2 Second sender value
     * @param receiver1 First receiver value
     * @param receiver2 Second receiver value
     * @returns HMAC signature as hexadecimal string
     */
    async HMAC(
        K: Point,
        senderId: string,
        receiverId: string,
        sender1: Point,
        sender2: Point,
        receiver1: Point,
        receiver2: Point,
    ): Promise<string> {
        const kcKey = await crypto.subtle.digest(
            "SHA-256",
            this.concatToBytes(K, "KC"),
        );
        const k = await crypto.subtle.importKey(
            "raw",
            kcKey,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"],
        );
        const bytes = this.concatToBytes(
            new Uint8Array(kcKey),
            senderId,
            receiverId,
            sender1,
            sender2,
            receiver1,
            receiver2,
        );
        return bytesToHex(
            new Uint8Array(await crypto.subtle.sign("HMAC", k, bytes)),
        );
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
    async createZKP(
        x: bigint,
        G: Point,
        X: Point,
        prover: string,
    ): Promise<ZKP> {
        const v = this.rand(1n, this.n - 1n);
        const V = G.multiply(v);
        const h = await this.H(G, V, X, prover);
        // r = v - (x * h) mod n
        const r = this.modN(v - x * h);
        return { h, r };
    }
    /**
     * Verify the given ZKP for the given generator, public key
     * and prover identity
     * @param zkp ZKP to verify
     * @param G Generator
     * @param X Public key
     * @param prover Prover identity
     */
    async verifyZKP(
        zkp: ZKP,
        G: Point,
        X: Point,
        prover: string,
    ): Promise<boolean> {
        const { h, r } = zkp;
        // check X is valid
        try {
            X.assertValidity();
        } catch {
            return false;
        }
        // V = G*r + X*h
        const V = G.multiply(r).add(X.multiply(h));
        // check h = H(G, V, X, prover)
        return h == (await this.H(G, V, X, prover));
    }
}
